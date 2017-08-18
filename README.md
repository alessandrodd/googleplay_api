# Google Play Unofficial Python 3 API Library

Based on the original googleplay-api project by Emilien Girault:
https://github.com/egirault/googleplay-api

An unofficial Python API that let you search, browse and download Android apps from Google Play (formerly Android Market).

## Disclaimer
**This is not an official API. I am not afiliated with Google in any way, and am not responsible of any damage that could be done with it. Use it at your own risk.**

## Dependencies
* [Python 3.5+](http://www.python.org)
* [Protocol Buffers](http://code.google.com/p/protobuf/)
* [Requests](http://docs.python-requests.org/en/master/)
* [Clint (used for command-line progress bar)](https://github.com/kennethreitz/clint)

You can install the required dependencies with _pip_ (a _requirements.txt_ file is provided for this purpose).

## Requirements
You must create a `config.ini` file before using the provided scripts (you can copy `config.ini.example` and modify the required fields). First, you need to provide your phone's `androidID`:

    # Google Service Framework ID (GSF ID)
    android_id = 1234567890ABCDEF

To get your `androidID`, use `*#*#8255#*#*` on your phone to start *Gtalk Monitor*. The hex string listed after `aid` is your `androidID`.

In order to authenticate to Google Play, you also need to provide either your Google login and password, or a valid Google Play Store token.

## Features

- Get package details (description, permissions, price...)
- Search for apps
- List apps in (sub)categories
- List apps similar to another app
- List categories and subcategories
- List reviews for a certain app
- Download apks
- Automatically throttle requests frequency to avoid server errors (Too Many Requests)
- Results paging

## Usage Examples
    >>> googleplay_api.googleplay import GooglePlayAPI
    >>> play_store = GooglePlayAPI(throttle=True)
    >>> play_store.login()
    >>> play_store.details("com.android.chrome")
    or
    >>> play_store.search("calculator app", maxResults=100)
    or
    >>> play_store.list("GAME_ARCADE", "apps_topselling_free")
    or
    >>> play_store.listSimilar("com.android.chrome")
    or
    >>> play_store.bulkDetails(["com.android.chrome", "org.mozilla.firefo"])
    or
    >>> play_store.getPages(play_store.search("calculator app"))
    or
    >>> play_store.browse("GAME_ARCADE")
    or
    >>> play_store.reviews("com.android.chrome")
    or
    >>> play_store.download("com.android.chrome", 307112552)

Check docstrings for more information.

## License

This project is released under the BSD license.

