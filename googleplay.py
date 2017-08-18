#!/usr/bin/python
import logging
import operator
from time import sleep

import requests
from google.protobuf import descriptor
from google.protobuf import text_format
from google.protobuf.internal.containers import RepeatedCompositeFieldContainer
from google.protobuf.message import Message

from . import config
from . import googleplay_pb2

MIN_THROTTLE_TIME = 0.05

ssl_verify = True


class LoginError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class RequestError(Exception):
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

    # https://developers.google.com/identity/protocols/AuthForInstalledApps
    URL_LOGIN = "https://android.clients.google.com/auth"
    ACCOUNT_TYPE_GOOGLE = "GOOGLE"
    ACCOUNT_TYPE_HOSTED = "HOSTED"
    ACCOUNT_TYPE_HOSTED_OR_GOOGLE = "HOSTED_OR_GOOGLE"
    authSubToken = None

    def __init__(self, androidId=None, lang=None, debug=False, throttle=False):
        """
        :param androidId: you must use a device-associated androidId value,
                          decides the kind of result that can be retrieved
        :param lang: language code to determine play store language, e.g. en_GB or it_IT or en_US
        :param debug: if True, prints debug info
        :param throttle: if True, in case of 429 errors (Too Many Requests), uses exponential backoff to
                         increase delay and retry request until success. If False, ignores 429 errors
        """
        self.preFetch = {}
        if androidId is None:
            androidId = config.get_option("android_id")
        if lang is None:
            lang = config.get_option("lang")
        if throttle:
            self.throttle_time = MIN_THROTTLE_TIME
        self.androidId = androidId
        self.lang = lang
        self.throttle = throttle
        self.downloadUserAgent = "AndroidDownloadManager/7.1 (Linux; U; Android 7.1; Pixel Build/NZZ99Z)"
        self.defaultAgentvername = "7.0.12.H-all [0]"
        self.defaultAgentvercode = "80701200"  # versionCode should be the version code of the Play Store app
        self.debug = debug

    def toDict(self, protoObj):
        """Converts the (protobuf) result from an API call into a dict, for
        easier introspection."""
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
        """Used for pretty printing a result from the API."""
        return text_format.MessageToString(protoObj)

    def _try_register_preFetch(self, protoObj):
        fields = [i.name for (i, _) in protoObj.ListFields()]
        if "preFetch" in fields:
            for p in protoObj.preFetch:
                self.preFetch[p.url] = p.response

    def setAuthSubToken(self, authSubToken):
        self.authSubToken = authSubToken

        # put your auth token in config.py to avoid multiple login requests
        if self.debug:
            print("authSubToken: " + authSubToken)

    def login(self, email=None, password=None, authSubToken=None):
        """Login to your Google Account. You must provide either:
        - an email and password
        - a valid Google authSubToken"""
        if email is None and password is None and authSubToken is None:
            # no parameter provided, loading from conf file
            email = config.get_option("google_login")
            password = config.get_option("google_password")
            authSubToken = config.get_option("auth_token")
        if authSubToken:
            self.setAuthSubToken(authSubToken)
        else:
            if not email or not password:
                raise Exception("You should provide at least authSubToken or (email and password)")
            params = {"Email": email,
                      "Passwd": password,
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
            }
            response = requests.post(self.URL_LOGIN, data=params,
                                     headers=headers, verify=ssl_verify)
            data = response.text.split()
            params = {}
            for d in data:
                if "=" not in d:
                    continue
                k, v = d.split("=")[0:2]
                params[k.strip().lower()] = v.strip()
            if "auth" in params:
                self.setAuthSubToken(params["auth"])
            elif "error" in params:
                raise LoginError("server says: " + params["error"])
            else:
                raise LoginError("Auth token not found.")

    def executeRequestApi2(self, path, sdk=25, agentvername=None, agentvercode=None, devicename="sailfish",
                           datapost=None, post_content_type="application/x-www-form-urlencoded; charset=UTF-8"):
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

            url = "https://android.clients.google.com/fdfe/{0}".format(path)
            response = None
            retry = True
            while retry:
                if self.throttle:
                    sleep(self.throttle_time)
                if datapost is not None:
                    response = requests.post(url, data=str(datapost), headers=headers, verify=ssl_verify)
                else:
                    response = requests.get(url, headers=headers, verify=ssl_verify)
                response_code = response.status_code
                if int(response_code) == 429 and self.throttle:
                    # there seems to be no "retry" header, so we have to resort to exponential backoff
                    self.throttle_time *= 2
                    logging.warning("Too many request reached. "
                                    "Throttling connection (sleep {0})...".format(self.throttle_time))
                else:
                    retry = False
                    if int(response_code) != 200:
                        logging.warning("Response code: {0} triggered by: {1} "
                                        "with datapost: {2}".format(response_code, url, str(datapost)))
                        logging.warning(response.content)
                    elif self.throttle and self.throttle_time > MIN_THROTTLE_TIME:
                        self.throttle_time /= 2

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

    def details(self, packageName):
        """
        Get app details from a package name.

        :param packageName: the app unique ID e.g. 'com.android.chrome' or 'org.mozilla.firefox'
        :return: details for packageName
        :rtype: DetailsResponse
        """
        path = "details?doc={0}".format(packageName)
        message = self.executeRequestApi2(path)
        return message.payload.detailsResponse

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

    def bulkDetails(self, packageNames):
        """
        Get several apps details from a list of package names.
        This is much more efficient than calling N times details() since it
        requires only one request.

        :param packageNames: a list of app unique ID e.g. ['com.android.chrome', 'org.mozilla.firefox']
        :return: details for the packages specified in packageNames
        :rtype: BulkDetailsResponse
        """
        path = "bulkDetails"
        req = googleplay_pb2.BulkDetailsRequest()
        req.docid.extend(packageNames)
        data = req.SerializeToString()
        message = self.executeRequestApi2(path, datapost=data.decode("utf-8"),
                                          post_content_type="application/x-protobuf")
        return message.payload.bulkDetailsResponse

    def bulkDetailsFromDocs(self, docs):
        """
        Utility method to retrieve details from a list of DocV2. Used mainly to retrieve details
        during pagination (getPages).

        :param docs: list of DocV2 documents
        :return: details for the packages specified in the documents
        :rtype: BulkDetailsResponse
        """
        packages = []
        for doc in docs:
            for child in doc.child:
                packages.append(child.docid)
        bulk_details = self.bulkDetails(packages)
        return bulk_details

    def getPages(self, response, maxPages=None, details=False):
        """
        Given a SearchResponse or ListResponse from e.g. listSimilar or search, returns the passed response
        merged to other maxPages-1 pages of responses (or less if not enough results are available).
        If details is True, returns the details for each app

        :param response: SearchResponse or ListResponse object
        :param maxPages: max number of pages to retrieve
        :param details: if True, returns the list of app details
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
            bulk_details = self.bulkDetailsFromDocs(response.doc)
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
            message = self.executeRequestApi2(next_page)
            response = operator.attrgetter(response_location)(message)
            if not response.doc:
                # break if there are no result
                break
            all_responses.MergeFrom(response)
            if details:
                bulk_details = self.bulkDetailsFromDocs(response.doc)
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

    def download(self, packageName, versionCode, offerType=1, progressBar=False):
        """
        Retrieves an apk.

        :param packageName: app unique ID e.g. 'com.android.chrome' or 'org.mozilla.firefox'
        :param versionCode: can be grabbed by using the details() method on the given
        :param offerType: seems to have no usage, default at 1
        :param progressBar: True if a progressbar should be shown
        :return: the apk content
        :rtype: str
        """
        path = "purchase"
        data = "ot={0}&doc={1}&vc={2}".format(offerType, packageName, versionCode)
        message = self.executeRequestApi2(path, datapost=data)

        url = message.payload.buyResponse.purchaseStatusResponse.appDeliveryData.downloadUrl
        cookie = message.payload.buyResponse.purchaseStatusResponse.appDeliveryData.downloadAuthCookie[0]

        cookies = {
            str(cookie.name): str(cookie.value)  # python-requests #459 fixes this
        }

        headers = {
            "User-Agent": self.downloadUserAgent,
            "Accept-Encoding": "",
        }

        if not progressBar:
            response = requests.get(url, headers=headers, cookies=cookies, verify=ssl_verify)
            return response.content
        # If progress_bar is asked
        from clint.textui import progress
        response_content = str()
        response = requests.get(url, headers=headers, cookies=cookies, verify=ssl_verify, stream=True)
        total_length = int(response.headers.get('content-length'))
        for chunk in progress.bar(response.iter_content(chunk_size=1024), expected_size=(total_length / 1024) + 1):
            if chunk:
                response_content += chunk
        return response_content
