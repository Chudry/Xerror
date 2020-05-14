from channels import Group
import json

# Channels consumers


def ws_connect(message):
    """Add client to group on connect"""
    Group('pool').add(message.reply_channel)


def ws_disconnect(message):
    """Remove client from group on disconnect"""
    Group('pool').discard(message.reply_channel)


def ws_recieve(message):
    """Message handler"""
    Group('pool').send({'text':
                        json.dumps({'message': message.content['text'],
                                    'sender': message.reply_channel.name})})
