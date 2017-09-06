import argparse

import os

import googleplay_api.config as play_conf
import requests
from googleplay_api.googleplay import GooglePlayAPI

emulated_device = play_conf.get_option("device")
play_store = GooglePlayAPI(throttle=True)


def get_details(package):
    print(play_store.details(package))


def get_latest_versioncode(package):
    # noinspection PyPep8Naming
    detailsResponse = play_store.details(package)
    return detailsResponse.docV2.details.appDetails.versionCode


def download_apk(package, version_code, output_path):
    if not version_code:
        version_code = get_latest_versioncode(package)
        print("Latest Version Code: {0}".format(version_code))
    data = play_store.download(package, version_code, progressBar=True)
    if not data:
        print("Error downloading apk.")
        return
    with open(output_path, "wb") as f:
        f.write(data)


def main():
    parser = argparse.ArgumentParser(
        description='Unofficial PlayStore python interface', add_help=True
    )
    parser.add_argument('--details', action="store", dest='package_to_detail', help='Shows various details for the '
                                                                                    'given package')
    group = parser.add_argument_group()
    group.add_argument('--download', action="store", dest='package_to_download', help='Download the apk with given '
                                                                                      'package name')
    group.add_argument('-o', action="store", dest='output_folder', help='(optional) Where to '
                                                                        'save the downloaded apk')
    group.add_argument('--version', action="store", dest='version_code', help='(optional) Version Code of the apk'
                                                                              'to download (default: latest)')
    parser.add_argument('--remote-token', action="store", dest='token_url', help='If the authentication token should be'
                                                                                 ' retrieved from a remote server')

    results = parser.parse_args()

    token = None
    if results.token_url:
        response = requests.get(results.token_url)
        token = response.text
        print("Using auth token: {0}".format(token))
    play_store.login(authSubToken=token)

    if results.package_to_detail:
        get_details(results.package_to_detail)
        return

    if results.package_to_download:
        package = results.package_to_download
        version = results.version_code
        output_folder = results.output_folder
        if output_folder:
            os.path.join(output_folder, package + ".apk")
        else:
            output_folder = package + ".apk"
        download_apk(results.package_to_download, version, output_folder)
        return

    parser.print_help()


if __name__ == '__main__':
    main()
