import configparser
import os

__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))

CONFIG_FILE = os.path.join(__location__, "config.ini")
MAIN_SEC = "Main"

c = configparser.ConfigParser()
c.read(CONFIG_FILE)


def config_section_map(section):
    dict1 = {}
    options = c.options(section)
    for option in options:
        try:
            dict1[option] = c.get(section, option)
        except configparser.NoSectionError or configparser.NoOptionError:
            dict1[option] = None
    return dict1


def get_option(opt):
    return config_section_map(MAIN_SEC)[opt]


# force the user to edit this file
if any([each is None for each in
        [get_option("android_id"), get_option("google_login"), get_option("google_password")]]):
    raise Exception("config.ini not updated")
