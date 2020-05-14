from channels import route
from parsing import consumers

# Channel routing


channel_routing = [
    route("websocket.connect", consumers.ws_connect),
    route("websocket.disconnect", consumers.ws_disconnect),
    route("websocket.recieve", consumers.ws_recieve)
]
