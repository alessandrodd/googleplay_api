#!/usr/bin/python
import logging
import operator
from collections import OrderedDict
from time import sleep
from urllib.parse import urlsplit, parse_qs, urlencode

import requests
from google.protobuf import descriptor
from google.protobuf import text_format
from google.protobuf.internal.containers import RepeatedCompositeFieldContainer
from google.protobuf.message import Message

from . import config
from . import googleplay_pb2
from . import crypt_utils

MIN_THROTTLE_TIME = 0.05
MAX_PREFETCH_ELEMENTS = 200

# should be always True, but we leave this here for testing purpose
ssl_verify = True
if not ssl_verify:
    # noinspection PyUnresolvedReferences
    import requests.packages.urllib3 as urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logging.warning("Warning: you are making unverified HTTPS requests!!!")


class LoginError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class RequestError(Exception):
    def __init__(self, value, http_status):
        self.value = value
        self.http_status = http_status

    def __str__(self):
        return repr(self.value)


class DownloadError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


# noinspection PyPep8Naming
class GooglePlayAPI(object):
    """
    Google Play Unofficial API Class

    Usual APIs methods are login(), search(), details(), bulkDetails(),
    download(), browse(), reviews() listSimilar() and list().

    toStr() can be used to pretty print the result (protobuf object) of the
    previous methods.

    toDict() converts the result into a dict, for easier introspection."""

    SERVICE = "androidmarket"

    URL_LOGIN = "https://android.clients.google.com/auth"
    ACCOUNT_TYPE_GOOGLE = "GOOGLE"
    ACCOUNT_TYPE_HOSTED = "HOSTED"
    ACCOUNT_TYPE_HOSTED_OR_GOOGLE = "HOSTED_OR_GOOGLE"

    def __init__(self, androidId=None, lang=None, debug=False, throttle=False, errorRetries=3, errorRetryTimeout=5,
                 proxies=None):
        """
        :param androidId: you must use a device-associated androidId value,
                          decides the kind of result that can be retrieved
        :param lang: language code to determine play store language, e.g. en_GB or it_IT or en_US
        :param debug: if True, prints debug info
        :param throttle: if True, in case of 429 errors (Too Many Requests), uses exponential backoff to
                         increase delay and retry request until success. If False, ignores 429 errors
        :param errorRetries: how many times retry to make a request that failed (except 429 HTTP status)
        :param errorRetryTimeout: how many second sleep after failing a request (except 429 HTTP status)
        :param proxies: a dictionary containing (protocol, address) key-value pairs, e.g.
                        {"http":"http://123.0.123.100:8080", "https": "https://231.1.2.34:3123"}
                        If None, no proxy will be used
        """
        self.preFetch = OrderedDict()
        if androidId is None:
            androidId = config.get_option("android_id")
        if lang is None:
            lang = config.get_option("lang")
        if throttle:
            self.throttleTime = MIN_THROTTLE_TIME
        if proxies is None:
            proxies = {}
            if config.get_option("http_proxy"):
                proxies["http"] = config.get_option("http_proxy")
            if config.get_option("https_proxy"):
                proxies["https"] = config.get_option("https_proxy")

        self.androidId = androidId
        self.lang = lang
        self.throttle = throttle
        self.errorRetries = errorRetries
        self.errorRetryTimeout = errorRetryTimeout
        self.downloadUserAgent = "AndroidDownloadManager/7.1 (Linux; U; Android 7.1; Pixel Build/NZZ99Z)"
        self.defaultAgentvername = "7.0.12.H-all [0]"  # updating these two values could broke the application
        self.defaultAgentvercode = "80701200"  # versionCode should be the version code of the Play Store app
        self.debug = debug
        self.proxies = proxies
        self.authSubToken = None
        self.email = None
        self.password = None

    def toDict(self, protoObj):
        """
        Converts the (protobuf) result from an API call into a dict, for
        easier introspection.

        :param protoObj: protobuf object
        :return: a dictionary or a list of dictionaries, depending on the protobuf object structure
        :rtype: Union[None, list, dict]
        """
        iterable = False
        if isinstance(protoObj, RepeatedCompositeFieldContainer):
            iterable = True
        else:
            protoObj = [protoObj]
        retlist = []

        for po in protoObj:
            msg = dict()
            for fielddesc, value in po.ListFields():
                # print value, type(value), getattr(value, "__iter__", False)
                if fielddesc.type == descriptor.FieldDescriptor.TYPE_GROUP or \
                        isinstance(value, RepeatedCompositeFieldContainer) or \
                        isinstance(value, Message):
                    # noinspection PyTypeChecker
                    msg[fielddesc.name] = self.toDict(value)
                else:
                    msg[fielddesc.name] = value
            retlist.append(msg)
        if not iterable:
            if len(retlist) > 0:
                return retlist[0]
            else:
                return None
        return retlist

    # noinspection PyMethodMayBeStatic
    def toStr(self, protoObj):
        """
        Used for pretty printing a result from the API.

        :param protoObj: protobuf object
        :return: a string representing the protobuf object
        :rtype: str
        """
        return text_format.MessageToString(protoObj)

    def _try_register_preFetch(self, protoObj):
        fields = [i.name for (i, _) in protoObj.ListFields()]
        if "preFetch" in fields:
            for p in protoObj.preFetch:
                self.preFetch[p.url] = p.response
        if 0 < MAX_PREFETCH_ELEMENTS < len(self.preFetch.keys()):
            # To avoid memory leaks, remove elements from dict when reaching limit.
            # Set MAX_PREFETCH_ELEMENTS to -1 to disable it
            difference = len(self.preFetch.keys()) - MAX_PREFETCH_ELEMENTS
            for i in range(difference):
                self.preFetch.popitem(False)  # False => FIFO

    def setAuthSubToken(self, authSubToken):
        self.authSubToken = authSubToken
        # put your auth token in config.ini to avoid multiple login requests
        if self.debug:
            print("authSubToken: " + authSubToken)

    def get_second_round_token(self, params, headers, token):
        new_params = params.copy()
        new_params["Token"] = token
        new_params["androidId"] = self.androidId
        new_params["check_email"] = "1"
        new_params["token_request_options"] = "CAA4AQ=="
        new_params["system_partition"] = "1"
        new_params["_opt_is_called_from_account_manager"] = "1"
        del new_params["Email"]
        del new_params["EncryptedPasswd"]
        response = requests.post(self.URL_LOGIN, data=new_params,
                                 headers=headers, verify=ssl_verify, proxies=self.proxies)
        data = response.text.split()
        response_params = {}
        for d in data:
            if "=" not in d:
                continue
            k, v = d.split("=")[0:2]
            response_params[k.strip().lower()] = v.strip()
        if "auth" in response_params:
            return response_params["auth"]
        elif "error" in response_params:
            logging.warning("server says: " + response_params["error"])
        else:
            logging.warning("Auth token not found in second round.")
        return None

    def login(self, email=None, password=None, authSubToken=None):
        """
        Login to your Google Account. You must provide either:
        - an email and password
        - a valid Google authSubToken

        :param email: your gmail email (e.g. example@gmail.com)
        :param password: password of tha gmail email
        :param authSubToken: Play Store authentication token, i.e. something like this:
                             AQVSHqIoXFwQM4oK57PKp7x3kzo17tk1cA-kAd77kpsPwoeyNNzDiQtQjJPgQuda-D25WA.
        """
        if email is None and password is None and authSubToken is None:
            # no parameter provided, loading from conf file
            email = config.get_option("google_login")
            password = config.get_option("google_password")
            authSubToken = config.get_option("auth_token")
        if authSubToken:
            self.setAuthSubToken(authSubToken)
        else:
            self.email = email
            self.password = password
            if not email or not password:
                raise LoginError("You should provide at least authSubToken or (email and password)")
            encrypted_password = crypt_utils.encrypt_login(email, password)
            params = {"Email": email,
                      "EncryptedPasswd": encrypted_password,
                      "service": self.SERVICE,
                      "accountType": self.ACCOUNT_TYPE_HOSTED_OR_GOOGLE,
                      "has_permission": "1",
                      "source": "android",
                      "androidId": self.androidId,
                      "app": "com.android.vending",
                      # "client_sig": self.client_sig,
                      "device_country": "en",
                      "operatorCountry": "en",
                      "lang": "en",
                      "sdk_version": "19"}
            headers = {
                "Accept-Encoding": "",
                "app": "com.android.vending",
            }
            response = requests.post(self.URL_LOGIN, data=params,
                                     headers=headers, verify=ssl_verify, proxies=self.proxies)
            data = response.text.split()
            response_params = {}
            for d in data:
                if "=" not in d:
                    continue
                k, v = d.split("=")[0:2]
                response_params[k.strip().lower()] = v.strip()
            if "token" in response_params:
                logging.info("Token found in response params. Trying to request a \"second round\" token.")
                second_round_token = self.get_second_round_token(params, headers, response_params["token"])
                if second_round_token is not None:
                    self.setAuthSubToken(second_round_token)
                    return
            if "auth" in response_params:
                self.setAuthSubToken(response_params["auth"])
            elif "error" in response_params:
                raise LoginError("server says: " + response_params["error"])
            else:
                raise LoginError("Auth token not found.")

    def executeRequestApi2(self, path, sdk=25, agentvername=None, agentvercode=None, devicename="sailfish",
                           datapost=None, post_content_type="application/x-www-form-urlencoded; charset=UTF-8"):
        """
        Builds and submits a valid request to the Google Play Store

        :param path: url path, depends on the endpoint that should be contacted
                     e.g. details?doc=com.android.chrome
        :param sdk: from which sdk version should the request appear to come from, e.g. 25
        :param agentvername: version name of the user agent, i.e. of the market app that we are spoofing;
                             used to build the User Agent
        :param agentvercode: version code of the user agent, i.e. of the market app that we are spoofing;
                             used to build the User Agent
        :param devicename: from which device should the request appear to come from; used to build the User Agent
        :param datapost: payload of the post request, if any
        :param post_content_type: content_type field of the post request
        :return: a protobuf object with the server response
        :rtype: ResponseWrapper
        """
        if not agentvername:
            agentvername = self.defaultAgentvername
        if not agentvercode:
            agentvercode = self.defaultAgentvercode
        user_agent = "Android-Finsky/" + agentvername + " (api=3,versionCode=" + agentvercode + ",sdk=" + \
                     str(sdk) + ",device=" + devicename + ",hardware=" + devicename + ",product=" + \
                     devicename + ",build=NZZ99Z:user)"
        if datapost is None and path in self.preFetch:
            data = self.preFetch[path]
        else:
            url = "https://android.clients.google.com/fdfe/{0}".format(path)
            response = None
            errorRetries = self.errorRetries
            retry = True
            while retry:
                if self.throttle:
                    sleep(self.throttleTime)

                headers = {"Accept-Language": self.lang,
                           "Authorization": "GoogleLogin auth={0}".format(self.authSubToken),
                           "X-DFE-Enabled-Experiments": "cl:billing.select_add_instrument_by_default",
                           "X-DFE-Unsupported-Experiments": "nocache:billing.use_charging_poller,"
                                                            "market_emails,buyer_currency,prod_baseline,"
                                                            "checkin.set_asset_paid_app_field,shekel_test,"
                                                            "content_ratings,buyer_currency_in_app,"
                                                            "nocache:encrypted_apk,recent_changes",
                           "X-DFE-Device-Id": self.androidId,
                           "X-DFE-Client-Id": "am-android-google",
                           # "X-DFE-Logging-Id": self.loggingId2, # Deprecated?
                           "User-Agent": user_agent,
                           "X-DFE-SmallestScreenWidthDp": "320",
                           "X-DFE-Filter-Level": "3",
                           # "X-DFE-No-Prefetch": 'true',  # avoid prefetch
                           "Accept-Encoding": "gzip, deflate",
                           "Host": "android.clients.google.com"}

                if datapost is not None:
                    headers["Content-Type"] = post_content_type
                if datapost is not None:
                    response = requests.post(url, data=datapost, headers=headers, verify=ssl_verify,
                                             proxies=self.proxies)
                else:
                    response = requests.get(url, headers=headers, verify=ssl_verify, proxies=self.proxies)
                response_code = response.status_code
                if int(response_code) == 429 and self.throttle:
                    # there seems to be no "retry" header, so we have to resort to exponential backoff
                    self.throttleTime *= 2
                    logging.warning("Too many request reached. "
                                    "Throttling connection (sleep {0})...".format(self.throttleTime))
                elif int(response_code) == 401 and errorRetries > 0 and self.password is not None and self.email is not None:
                    logging.warning("Received 401; trying to obtain a new subAuth token from credentials")
                    self.login(self.email, self.password)
                    errorRetries -= 1
                elif int(response_code) != 200:
                    logging.error("Response code: {0} triggered by: {1} "
                                  "with datapost: {2}".format(response_code, url, str(datapost)))
                    logging.error(response.content)
                    if errorRetries <= 0:
                        raise RequestError("Error during http request: {0}".format(response_code), response_code)
                    else:
                        sleep(max(self.throttleTime, self.errorRetryTimeout))
                        errorRetries -= 1
                else:
                    retry = False
                    if self.throttle and self.throttleTime > MIN_THROTTLE_TIME:
                        retry = False
                        self.throttleTime /= 2

            data = response.content
        '''
        data = StringIO.StringIO(data)
        gzipper = gzip.GzipFile(fileobj=data)
        data = gzipper.read()
        '''
        message = googleplay_pb2.ResponseWrapper.FromString(data)
        self._try_register_preFetch(message)

        # Debug
        # print(text_format.MessageToString(message))
        if not str(message) or not str(message.payload):
            logging.warning(data)
        return message

    #####################################
    # Google Play API Methods
    #####################################

    def freeRequest(self, path, datapost=None):
        """
        Do a generic request, useful for debugging

        :param path: request path
        :param datapost: post data (if any)
        :return: Message
        """
        return self.executeRequestApi2(path, datapost=datapost)

    def details(self, packageName, getPrefetchPages=False):
        """
        Get app details from a package name.

        :param packageName: the app unique ID e.g. 'com.android.chrome' or 'org.mozilla.firefox'
        :param getPrefetchPages: if True, also returns the pre-fetched pages that were sent by the server.
                             These pages will be already in cache after the details request, so requesting
                             these will not result in a remote call.
        :return: details for packageName
        :rtype: Union[DetailsResponse, (DetailsResponse, dict)]
        """
        path = "details?doc={0}".format(packageName)
        message = self.executeRequestApi2(path)
        if not getPrefetchPages:
            return message.payload.detailsResponse
        else:
            prefetchedPages = {}
            for prefetch in message.preFetch:
                prefetchMessage = self.executeRequestApi2(prefetch.url)
                listResponse = prefetchMessage.payload.listResponse
                for doc in listResponse.doc:
                    if doc.backendDocid == ("similar_apps_" + packageName):
                        if prefetchedPages.get("similar", None) is not None:
                            logging.error("Similar page already prefetched for package {0}!".format(packageName))
                        else:
                            prefetchedPages["similar"] = listResponse
                    elif doc.backendDocid == ("pre_install_users_also_installed_" + packageName):
                        if prefetchedPages.get("preInstall", None) is not None:
                            logging.error("Pre-install page already prefetched for package {0}!".format(packageName))
                        else:
                            prefetchedPages["preInstall"] = listResponse
                    elif doc.backendDocid == ("post_install_users_also_installed_" + packageName):
                        if prefetchedPages.get("postInstall", None) is not None:
                            logging.error("Post-install page already prefetched for package {0}!".format(packageName))
                        else:
                            prefetchedPages["postInstall"] = listResponse
                    else:
                        logging.error("Unknown prefetch: {1} for package {0}!".format(packageName, doc.backendDocid))

            return message.payload.detailsResponse, prefetchedPages

    def search(self, query, maxResults=None, offset=None):
        """
        Search for apps.

        :param query: Query to submit, e.g. 'best riddles game'
        :param maxResults: max result per page; WARNING despite being seen as parameter during play store
                              Reverse Engineering, it seems to be ignored by the server (fixed to 20);
                              use getPages for more results
        :param offset: skip the first offset results
        :return: search results for the submitted query
        :rtype: SearchResponse

        """
        path = "search?c=3&q={0}".format(requests.utils.quote(query))  # TODO handle categories
        if maxResults is not None:
            path += "&n={0}".format(int(maxResults))
        if offset is not None:
            path += "&o={0}".format(int(offset))

        message = self.executeRequestApi2(path)
        return message.payload.searchResponse

    def list(self, cat=None, ctr=None, maxResults=None, offset=None):
        """
        List apps for a given category-subcategory pair, subcategories if only category is provided.

        :param cat: category id, e.g. AUTO_AND_VEHICLES or GAME_ARCADE
        :param ctr: subcategory id, e.g. apps_topselling_free or apps_movers_shakers
        :param maxResults: max number of results, WARNING: seems to be capped at 100, error for higher values;
                             use getPages for more results
        :param offset: skip the first offset results
        :return: apps for given category-subcategory OR list of subcategories if only cat provided
        :rtype: ListResponse
        """
        path = "list?c=3&cat={0}".format(cat)
        if ctr is not None:
            path += "&ctr={0}".format(ctr)
        if maxResults is not None:
            path += "&n={0}".format(int(maxResults))
        if offset is not None:
            path += "&o={0}".format(int(offset))
        message = self.executeRequestApi2(path)
        return message.payload.listResponse

    def listSimilar(self, packageName, maxResults=None, offset=None):
        """
        List apps similar to a given package.

        :param packageName: the app unique ID e.g. 'com.android.chrome' or 'org.mozilla.firefox'
        :param maxResults: max number of results, WARNING: seems to be capped at 100, error for higher values;
                             use getPages for more results
        :param offset: skip the first offset results
        :return: apps similar to the app identified by packageName
        :rtype: ListResponse
        """
        # Check this url for further analysis
        # browseV2?bt=5&c=3&doc=com.android.chrome&rt=1
        path = "rec?c=3&rt=1&doc={0}".format(packageName)
        if maxResults is not None:
            path += "&n={0}".format(int(maxResults))
        if offset is not None:
            path += "&o={0}".format(int(offset))

        message = self.executeRequestApi2(path)
        return message.payload.listResponse

    def bulkDetails(self, packageNames, includeChildDocs=False, includeDetails=False):
        """
        Get several apps details from a list of package names.
        This is much more efficient than calling N times details() since it
        requires only one request.

        :param packageNames: a list of app unique ID e.g. ['com.android.chrome', 'org.mozilla.firefox']
        :param includeChildDocs: include child docs if presents
        :param includeDetails: include more details, such as html description and so on
        :return: details for the packages specified in packageNames
        :rtype: BulkDetailsResponse
        """
        path = "bulkDetails"
        req = googleplay_pb2.BulkDetailsRequest()
        req.docid.extend(packageNames)
        req.includeChildDocs = includeChildDocs
        req.includeDetails = includeDetails
        data = req.SerializeToString()
        message = self.executeRequestApi2(path, datapost=data,
                                          post_content_type="application/x-protobuf")
        return message.payload.bulkDetailsResponse

    def bulkDetailsFromDocs(self, docs, includeChildDocs=False, includeDetails=False):
        """
        Utility method to retrieve details from a list of DocV2. Used mainly to retrieve details
        during pagination (getPages).

        :param docs: a list of DocV2 documents
        :param includeChildDocs: include child docs if presents
        :param includeDetails: include more details, such as html description and so on
        :return: details for the packages specified in the documents
        :rtype: BulkDetailsResponse
        """
        packages = []
        for doc in docs:
            for child1 in doc.child:
                if child1.docType == 45:
                    for child2 in child1.child:
                        if child2.docType == 1:
                            packages.append(child2.docid)
                        else:
                            logging.warning("Unknown docType {0}. Maybe it's not an app?".format(child1.docType))
                elif child1.docType == 1:
                    packages.append(child1.docid)
                else:
                    logging.warning("Unknown docType {0}. Maybe it's not an app?".format(child1.docType))
        bulk_details = self.bulkDetails(packages, includeChildDocs, includeDetails)
        return bulk_details

    def getPages(self, response, maxPages=None, alterMaxResults=None, details=False, includeChildDocs=False,
                 includeDetails=False):
        """
        Given a SearchResponse or ListResponse from e.g. listSimilar or search, returns the passed response
        merged to other maxPages-1 pages of responses (or less if not enough results are available).
        If details is True, returns the details for each app

        :param response: SearchResponse or ListResponse object
        :param maxPages: max number of pages to
        :param alterMaxResults: if set to a number, it tries to detect pagination parameters and
                                   increment it to the desired amount. Usually ok for values <= 100
        :param details: if True, returns the list of app details
        :param includeChildDocs: (valid only if details is True) include child docs if presents
        :param includeDetails: (valid only if details is True) include more details, such as html description and so on
        :return: a list of apps or app details
        :rtype: SearchResponse or ListResponse or BulkDetailsResponse
        """
        # if response doesn't contain any doc, return directly the response or None if details were requested
        if not response.doc:
            if details:
                return None
            else:
                return response
        if type(response) == googleplay_pb2.SearchResponse:
            response_location = "payload.searchResponse"
        elif type(response) == googleplay_pb2.ListResponse:
            response_location = "payload.listResponse"
        else:
            logging.error("Unknown response type: {0}; cannot get pages")
            return
        all_responses = response
        all_details = None
        if details:
            bulk_details = self.bulkDetailsFromDocs(response.doc, includeChildDocs, includeDetails)
            all_details = bulk_details
        page = 1
        next_page = response.doc[-1].containerMetadata.nextPageUrl
        while True:
            if maxPages and page >= maxPages:
                # break if we have reached the imposed limit
                break
            if not next_page:
                # break if there isn't any page left
                break
            if alterMaxResults and "n=" in next_page:
                # parse original string url
                url_data = urlsplit(next_page)
                # parse original query-string
                qs_data = parse_qs(url_data.query)
                # manipulate the query-string
                qs_data['n'] = [alterMaxResults]
                # get the url with modified query-string
                # noinspection PyProtectedMember
                next_page = url_data._replace(query=urlencode(qs_data, True)).geturl()

            message = self.executeRequestApi2(next_page)
            response = operator.attrgetter(response_location)(message)
            if not response.doc:
                # break if there are no result
                break
            all_responses.MergeFrom(response)
            if details:
                bulk_details = self.bulkDetailsFromDocs(response.doc, includeChildDocs, includeDetails)
                all_details.MergeFrom(bulk_details)
            page += 1
            next_page = response.doc[-1].containerMetadata.nextPageUrl

        if details:
            return all_details
        return all_responses

    def browse(self, cat=None, ctr=None):
        """
        Browse categories; cat (category ID) and ctr (subcategory ID) are used as filters.

        :param cat: category id, e.g. AUTO_AND_VEHICLES or GAME_ARCADE
        :param ctr: subcategory id, e.g. apps_topselling_free or apps_movers_shakers
        :return: list of categories or subcategories, if cat is provided
        :rtype: BrowseResponse
        """
        path = "browse?c=3"
        if cat is not None:
            path += "&cat={0}".format(cat)
        if ctr is not None:
            path += "&ctr={0}".format(ctr)
        message = self.executeRequestApi2(path)
        return message.payload.browseResponse

    def reviews(self, packageName, filterByDevice=False, sort=2, maxResults=None, offset=None):
        """
        Browse reviews.

        :param packageName: app unique ID e.g. 'com.android.chrome' or 'org.mozilla.firefox'
        :param filterByDevice: if True, return only reviews for your device
        :param sort: sort index
        :param maxResults: max number of results, WARNING: seems to be capped at 100, error for higher values;
                             change offset for more results
        :param offset: skip the first offset results
        :return: a list of reviews
        :rtype: ReviewResponse
        """
        path = "rev?doc={0}&sort={1}".format(packageName, sort)
        if maxResults is not None:
            path += "&n={0}".format(int(maxResults))
        if offset is not None:
            path += "&o={0}".format(int(offset))
        if filterByDevice:
            path += "&dfil=1"
        message = self.executeRequestApi2(path)
        return message.payload.reviewResponse

    def purchase(self, packageName, versionCode, offerType=1):
        """
        Purchases an app. Can be used with free apps too.

        :param packageName: app unique ID e.g. 'com.android.chrome' or 'org.mozilla.firefox'
        :param versionCode: can be grabbed by using the details() method on the given
        :param offerType: seems to have no usage, default at 1
        :return: purchase response
        :rtype: BuyResponse
        """
        path = "purchase"
        data = "doc={0}&ot={1}&vc={2}".format(packageName, offerType, versionCode)
        message = self.executeRequestApi2(path, datapost=data)
        return message.payload.buyResponse

    def delivery(self, packageName, versionCode, offerType=1):
        """
        Delivers a purchased or free app, used to retrieve download link.

        :param packageName: app unique ID e.g. 'com.android.chrome' or 'org.mozilla.firefox'
        :param versionCode: can be grabbed by using the details() method on the given
        :param offerType: seems to have no usage, default at 1
        :return: delivery response
        :rtype: DeliveryResponse
        """
        path = "delivery"
        path += "?doc={0}&ot={1}&vc={2}".format(packageName, offerType, versionCode)
        message = self.executeRequestApi2(path)
        return message.payload.deliveryResponse

    def download(self, packageName, versionCode, offerType=1, progressBar=False):
        """
        Retrieves an apk.

        :param packageName: app unique ID e.g. 'com.android.chrome' or 'org.mozilla.firefox'
        :param versionCode: can be grabbed by using the details() method on the given
        :param offerType: seems to have no usage, default at 1
        :param progressBar: True if a progressbar should be shown
        :return: the apk content
        :rtype: Union[None, bytes, str]
        """
        # first "purchase" the app, then "deliver" it if it was already purchased
        try:
            response = self.purchase(packageName, versionCode, offerType)
        except RequestError as e:
            raise DownloadError(str(e))
        url = response.purchaseStatusResponse.appDeliveryData.downloadUrl
        if len(response.purchaseStatusResponse.appDeliveryData.downloadAuthCookie) > 0:
            cookie = response.purchaseStatusResponse.appDeliveryData.downloadAuthCookie[0]
        else:
            try:
                response = self.delivery(packageName, versionCode, offerType)
            except RequestError as e:
                raise DownloadError(str(e))
            url = response.appDeliveryData.downloadUrl
            if len(response.appDeliveryData.downloadAuthCookie) > 0:
                cookie = response.appDeliveryData.downloadAuthCookie[0]
            else:
                logging.error(response)
                raise DownloadError("Can't find download Authentication Cookie")

        cookies = {
            str(cookie.name): str(cookie.value)  # python-requests #459 fixes this
        }

        headers = {
            "User-Agent": self.downloadUserAgent,
            "Accept-Encoding": "",
        }

        if not progressBar:
            response = requests.get(url, headers=headers, cookies=cookies, verify=ssl_verify, proxies=self.proxies)
            return response.content
        # If progress_bar is asked
        from clint.textui import progress
        response_content = bytes()
        response = requests.get(url, headers=headers, cookies=cookies, verify=ssl_verify, stream=True,
                                proxies=self.proxies)
        total_length = int(response.headers.get('content-length'))
        for chunk in progress.bar(response.iter_content(chunk_size=1024), expected_size=(total_length / 1024) + 1):
            if chunk:
                response_content += chunk
        return response_content
