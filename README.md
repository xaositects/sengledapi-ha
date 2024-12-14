I forked this to fix an error in the request class as the original is no longer maintained. It is known to work with HA 2024.12.02 but there are deprecated light constants that will need to be updated prior to 2025.01.01 as they will be removed



# Home Assistant - Sengled Bulb Integration

This is a custom component to allow control of Sengled Bulbs in Homeassistant using the unofficial Sengled API. Please note this mimics the Sengled app and therefore Sengled may cut off access at anytime.

# Supported Bulbs from Sengled
You can find [Supported Products](https://github.com/xaositects/sengledapi-ha/wiki) here. If you have other bulbs that are not on this list and they do work, you can create a pull request to have the wiki updated.



### Highlights of what **SengledApi** can do

* Control Sengled Bulbs as lights through HA
* Control Sengled Light Switch through HA

### Potential Downsides

* This is an unofficial implementation of the api and therefore may be disabled or broken at anytime by Sengled
* I only have Element Classic A19 Kit (Light bulbs + Hub) https://us.sengled.com/products/element-classic-kit and the Wifi LED Multicolor A19 Bulb https://us.sengled.com/products/sengled-smart-wi-fi-led-multicolor-a19-bulb to test.

* An update from Sengled may break this integration without my knowledge. **Please use the betas as they become avaliable**

** Wifi bulbs are supported by adding ```wifi: true``` to your configuration. All functions should be supported.

## Installation (HACS) - Highly Recommended

1. Have HACS installed, this will allow you to easily update
2. Add [https://github.com/xaositects/sengledapi-ha](https://github.com/xaositects/sengledapi-ha) as a custom repository as Type: Integration
3. Click install under "Sengled Bulb Integration" in the Integration tab
4. Restart HA

## Installation (Manual)
**Note: "requirements": ["paho-mqtt==1.5.0"]
1. Download this repository as a ZIP (green button, top right) and unzip the archive
2. Copy `/custom_components/sengledapi` to your `<config_dir>/` directory
   * On Hassio the final location will be `/config/custom_components/sengledapi`
   * On Hassbian the final location will be `/home/homeassistant/.homeassistant/custom_components/sengledapi`
3. Restart HA

## **SengledApi** NOTE: Configuration Changed Please update.
Country Code example:
* country: us
* country: au
* country: it
* country: eu

## Configuration

Add the following to your configuration file `configuration.yaml`. Update with your own information.

```yaml
sengledapi:
  username: sengledusername@gmail.com
  password: sengledPassword
  country: us
  wifi: true
```

## Usage

* Restart HA

* Entities will show up as `light.<friendly name>`, `switch.<friendly name>` for example (`light.livingroom_lamp`).

## Reporting an Issue

1. Setup your logger to print debug messages for this component by adding this to your `configuration.yaml`:
    ```yaml
    logger:
      default: warning
      logs:
        custom_components.sengledapi: debug
    ```
2. Restart HA
3. Verify you're still having the issue
4. File an issue in this Github Repository
