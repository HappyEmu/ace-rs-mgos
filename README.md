# Mongoose OS ACE Resource Server
This repository holds a proof-of-concept implementation for a resource server proposed in the IETF ACE draft
document: https://tools.ietf.org/pdf/draft-ietf-ace-oauth-authz-12.pdf. It uses Mongoose OS as a development platform
and was tested using a Widora AIR ESP32 development board. You can learn more about Mongoose OS here: https://mongoose-os.com/docs/README.md

This implementation is to be used along with the authorization server and client implementation from: https://github.com/HappyEmu/ace

### Getting Started

#### Building
To build the firmware, use

    ~/.mos/bin/mos build --platform esp32

#### Flashing
To flash the built firmware to the device, run

    ~/.mos/bin/mos flash --port /dev/cu.{YOUR_PORT_HERE}

#### Connect to Console
You can inspect the running program using 

    ~/.mos/bin/mos console --port /dev/cu.{YOUR_PORT_HERE}

If you see a lot of `x`s in the terminal, you can try to reset the device.

#### Connect to WiFi
Your device should be in the same network as the authorization server and client. You can instruct the device
to connect to your WiFi network using

    ~/.mos/bin/mos console {WIFI_NETWORK_NAME} {WIFI_PASSWORD} --port /dev/cu.{YOUR_PORT_HERE}

### Resources
This RS implementation exposes two protected resources

    [GET] /temperature
    [POST] /led

The temperature endpoint reports the temperature and humidity value of an attached DHT22 sensor. The LED endpoint
allows the attached LED to be enabled or disabled.