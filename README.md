# ARRIS 3442 (Vodafone Station) Device Tracker for Home Assistant

This is the first kinda working commit of this project. Please feel free to try it and give feedback.

This repository allows users to create a custom component to use the arris3442 router device tracker. The router is mainly distributed by Vodafone as "Vodafone Station" for DOCSIS 3.1 cable based connections.

The code to log into the router was mainly forked from https://github.com/diveflo/arris-tg3442-reboot. 

Installation:
1. In the Home Assistant config folder, create a custom_components/arris3442 folder.
2. Copy __init__.py, device_tracker.py and manifest.json from this repository into the new folder.
3. Restart Home Assistant
4. Add the device_tracker / arris3442 configuration into the configuration.yaml file.
5. Restart Home Assistant


Example Config:

```
device_tracker:
  - platform: arris3442
    host: ROUTER_IP_ADDRESS (with http://)
    username: ROUTER_USERNAME
    password: !secret arris_router_password
```

To verify Home Assistant is seeing the devices that are connected to the router, navigate to Developer Tools -> States and search for entities that start with device_tracker. The devices should show up with a source_type attribute of router.

A known_devices.yaml file should be created that can be edited to further customize the appearance of the tracked devices. For more information see https://www.home-assistant.io/integrations/device_tracker/.


