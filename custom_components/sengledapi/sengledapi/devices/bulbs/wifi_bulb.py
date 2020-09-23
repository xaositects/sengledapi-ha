"""Sengled Bulb Integration."""

import asyncio
import logging
import time
import json

from .bulbproperty import BulbProperty

_LOGGER = logging.getLogger(__name__)
_LOGGER.info("SengledApi: Initializing Wifi Bulbs")


class WifiColorBulb:
    def __init__(
        self,
        api,
        device_mac,
        friendly_name,
        state,
        device_model,
        support_color_temp,
        support_brightness,
        isonline,
        jsession_id,
        country,
    ):
        _LOGGER.debug("SengledApi: Wifi Bulb %s initializing.", friendly_name)

        self._api = api
        self._device_mac = device_mac
        self._friendly_name = friendly_name
        self._state = state
        self._avaliable = isonline
        self._just_changed_state = False
        self._device_model = device_model
        self._jsession_id = jsession_id
        self._device_rssi = None
        self._country = None
        self._brightness = 0
        self._color_temperature = 0
        self._color = 0
        self._rgb_color_r = 0
        self._rgb_color_g = 0
        self._rgb_color_b = 0
        self._colorMode = 0
        self._alarm_status = None
        self._support_color_temp = support_color_temp
        self._support_brightness = support_brightness

        self._api._subscribe_mqtt(
            "wifielement/{}/status".format(self._device_mac),
            self._update_status,
        )

    async def async_turn_on(self):
        _LOGGER.debug(
            "SengledApi: Wifi Color Bulb "
            + self._friendly_name
            + " "
            + self._device_mac
            + " .turning on"
        )
        data = {
            "dn": self._device_mac,
            "type": "switch",
            "value": "1",
            "time": int(time.time() * 1000),
        }

        self._api._publish_mqtt(
            "wifielement/{}/update".format(self._device_mac),
            json.dumps(data),
        )

        self._state = True
        self._just_changed_state = True

    async def async_set_brightness(self, brightness):
        brightness_precentage = round((brightness / 255) * 100)

        _LOGGER.debug(
            "SengledApi: Wifi Color Bulb "
            + self._friendly_name
            + " "
            + self._device_mac
            + " setting Brightness "
            + str(brightness_precentage)
        )

        data_brightness = {
            "dn": self._device_mac,
            "type": "brightness",
            "value": str(brightness_precentage),
            "time": int(time.time() * 1000),
        }
        self._state = True
        self._just_changed_state = True
        self._api._publish_mqtt(
            "wifielement/{}/update".format(self._device_mac),
            json.dumps(data_brightness),
        )

    async def async_color_temperature(self, colorTemperature):
        _LOGGER.debug(
            "SengledApi: Wifi Color Bulb "
            + self._friendly_name
            + " "
            + self._device_mac
            + " .Setting ColorTemp"
        )
        _LOGGER.info("SengledApi: color Temp from HA %s", str(colorTemperature))
        color_temperature_precentage = round(
            self.translate(int(colorTemperature), 2000, 6500, 1, 100)
        )
        _LOGGER.info("SengledApi: color Temp %s", color_temperature_precentage)
        data_color_temperature = {
            "dn": self._device_mac,
            "type": "colorTemperature",
            "value": str(color_temperature_precentage),
            "time": int(time.time() * 1000),
        }
        self._state = True
        self._just_changed_state = True
        self._api._publish_mqtt(
            "wifielement/{}/update".format(self._device_mac),
            json.dumps(data_color_temperature),
        )

    async def async_set_color(self, color):
        _LOGGER.debug(
            "SengledApi: Wifi Color Bulb "
            + self._friendly_name
            + " "
            + self._device_mac
            + " .Setting Color"
        )

        mycolor = str(color)
        for r in ((" ", ""), (",", ":"), ("(", ""), (")", "")):
            mycolor = mycolor.replace(*r)

        _LOGGER.info("SengledApi: Wifi Set Color %s", str(mycolor))
        data_color = {
            "dn": self._device_mac,
            "type": "color",
            "value": mycolor,
            "time": int(time.time() * 1000),
        }
        self._state = True
        self._just_changed_state = True
        self._api._publish_mqtt(
            "wifielement/{}/update".format(self._device_mac),
            json.dumps(data_color),
        )

    async def async_turn_off(self):
        _LOGGER.debug(
            "SengledApi: Wifi Color Bulb "
            + self._friendly_name
            + " "
            + self._device_mac
            + " turning off."
        )

        data = {
            "dn": self._device_mac,
            "type": "switch",
            "value": "0",
            "time": int(time.time() * 1000),
        }
        self._api._publish_mqtt(
            "wifielement/{}/update".format(self._device_mac),
            json.dumps(data),
        )
        self._state = False
        self._just_changed_state = True

    def is_on(self):
        return self._state

    async def async_update(self):
        _LOGGER.debug(
            "SengledApi: Wifi Bulb "
            + self._friendly_name
            + " "
            + self._device_mac
            + " updating."
        )
        if self._just_changed_state:
            self._just_changed_state = False
        else:
            bulbs = []
            url = "https://life2.cloud.sengled.com/life2/device/list.json"
            payload = {}

            data = await self._api.async_do_request(url, payload, self._jsession_id)

            _LOGGER.info("SengledApi: Wifi Bulb " + self._friendly_name + " updating.")
            for item in data["deviceList"]:
                # _LOGGER.debug("SengledApi: Wifi Bulb update return " + str(item))
                bulbs.append(BulbProperty(self, item, True))
            for items in bulbs:
                if items.uuid == self._device_mac:
                    self._friendly_name = items.name
                    self._state = items.switch
                    self._avaliable = items.isOnline
                    self._device_rssi = items.device_rssi
                    # Supported Features
                    self._brightness = round((int(items.brightness) / 100) * 255)
                    self._color_temperature = int(items.color_temperature)
                    self._color = items.color

    def _update_status(self, message):
        """
        Update the status from an incoming MQTT message.
        message -- the incoming message. This is not used.
        """
        try:
            data = json.loads(message)
            _LOGGER.debug("SengledApi: Update Status from MQTT %s", str(data))
        except ValueError:
            return

        for status in data:
            if "type" not in status or "dn" not in status:
                continue

            if status["dn"] == self._device_mac:
                if status["type"] == "color":
                    self._color = status["value"]
                if status["type"] == "colorMode":
                    self._color_mode = status["value"]
                if status["type"] == "brightness":
                    self._brightness = status["value"]
                if status["type"] == "colorTemperature":
                    self._color_temperature = status["value"]

    def set_attribute_update_callback(self, callback):
        """
        Set the callback to be called when an attribute is updated.
        callback -- callback
        """
        self._attribute_update_callback = callback

    @staticmethod
    def _attribute_to_property(attr):
        attr_map = {
            "consumptionTime": "consumption_time",
            "deviceRssi": "rssi",
            "identifyNO": "identify_no",
            "productCode": "product_code",
            "saveFlag": "save_flag",
            "startTime": "start_time",
            "supportAttributes": "support_attributes",
            "timeZone": "time_zone",
            "typeCode": "type_code",
        }

        return attr_map.get(attr, attr)


class WifiBulb:
    def __init__(
        self,
        api,
        device_mac,
        friendly_name,
        state,
        device_model,
        isonline,
        support_color_temp,
        support_brightness,
        jsession_id,
        country,
    ):
        _LOGGER.debug("SengledApi: Wifi Bulb %s initializing.", friendly_name)

        self._api = api
        self._device_mac = device_mac
        self._friendly_name = friendly_name
        self._state = state
        self._avaliable = isonline
        self._just_changed_state = False
        self._device_model = device_model
        self._brightness = 0
        self._color_temperature = 0
        self._color = 0
        self._rgb_color_r = 0
        self._rgb_color_g = 0
        self._rgb_color_b = 0
        self._device_rssi = 0
        self._support_color_temp = support_color_temp
        self._support_brightness = support_brightness
        self._jsession_id = jsession_id
        self._country = country
        self._alarm_status = None

    async def async_turn_on(self):
        """Turn on Wifi Bulb"""
        _LOGGER.debug(
            "SengledApi: Wifi Color Bulb %s %s is turing on.",
            self._friendly_name,
            self._device_mac,
        )
        data = {
            "dn": self._device_mac,
            "type": "switch",
            "value": "1",
            "time": int(time.time() * 1000),
        }

        self._api._publish_mqtt(
            "wifielement/{}/update".format(self._device_mac),
            json.dumps(data),
        )
        self._state = True
        self._just_changed_state = True

    async def async_set_brightness(self, brightness):
        brightness_precentage = round((brightness / 255) * 100)

        _LOGGER.debug(
            "SengledApi: Wifi Color Bulb "
            + self._friendly_name
            + " "
            + self._device_mac
            + " setting Brightness "
            + str(brightness_precentage)
        )

        data_brightness = {
            "dn": self._device_mac,
            "type": "brightness",
            "value": str(brightness_precentage),
            "time": int(time.time() * 1000),
        }
        self._state = True
        self._just_changed_state = True
        self._api._publish_mqtt(
            "wifielement/{}/update".format(self._device_mac),
            json.dumps(data_brightness),
        )

    async def async_turn_off(self):
        _LOGGER.debug(
            "SengledApi: Wifi Color Bulb "
            + self._friendly_name
            + " "
            + self._device_mac
            + " turning off."
        )

        data = {
            "dn": self._device_mac,
            "type": "switch",
            "value": "0",
            "time": int(time.time() * 1000),
        }
        self._api._publish_mqtt(
            "wifielement/{}/update".format(self._device_mac),
            json.dumps(data),
        )
        self._state = False
        self._just_changed_state = True

    def is_on(self):
        return self._state

    async def async_update(self):
        _LOGGER.debug(
            "SengledApi: Wifi Bulb "
            + self._friendly_name
            + " "
            + self._device_mac
            + " updating."
        )
        if self._just_changed_state:
            self._just_changed_state = False
        else:
            bulbs = []
            url = "https://life2.cloud.sengled.com/life2/device/list.json"
            payload = {}

            data = await self._api.async_do_request(url, payload, self._jsession_id)

            _LOGGER.info("SengledApi: Wifi Bulb " + self._friendly_name + " updating.")
            for item in data["deviceList"]:
                _LOGGER.debug("SengledApi: Wifi Bulb update return " + str(item))
                bulbs.append(BulbProperty(self, item, True))
            for items in bulbs:
                if items.uuid == self._device_mac:
                    self._friendly_name = items.name
                    self._state = items.switch
                    self._avaliable = items.online
                    self._device_rssi = items.device_rssi
                    # Supported Features
                    self._brightness = round((items.brightness / 100) * 255)