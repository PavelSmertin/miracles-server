#!/usr/bin/env python

import os

from functools import partial
import logging

import connexion
from connexion_sql_utils import crud


from rauth import OAuth2Service
import json
import time
from werkzeug.exceptions import Unauthorized
import jwt
import six


from flask import Flask, render_template, redirect
from flask_socketio import SocketIO, emit
from flask import request


from connexion import NoContent
from sqlalchemy import Column, Date, Integer, Text, create_engine, inspect, desc
from sqlalchemy.orm import joinedload
from sqlalchemy.sql import func
from datetime import datetime
from models import ModelBase, Session, DbModel, DbModelClear, engine, User, Message, Tag, Visits, Socials


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Most of this would typically be in a different module, but since
# this is just an example, I'm sticking it all into this module.

JWT_ISSUER = 'club.miracles.app'
JWT_SECRET = '8F@%P51xGy'
JWT_LIFETIME_SECONDS = 3600 * 24 * 365
JWT_ALGORITHM = 'HS256'


get_user_id     = partial(crud.get_id, User, user_id=None)
put_user        = partial(crud.put, User, user_id=None, user_data=None)

get_message_id  = partial(crud.get_id, Message, message_id=None)
put_message     = partial(crud.put, Message, message_id=None, message_data=None)
delete_message  = partial(crud.delete, Message, message_id=None)


client_id='187087565689839'
client_secret='56ca69b06b90f5692eaf8f1aeb41f9ac'
authorize_url = 'https://www.facebook.com/v6.0/dialog/oauth'
access_token_url = 'https://graph.facebook.com/v6.0/oauth/access_token'

redirect_uri='https://api.miracles.club/oauth2-redirect.html'
request_uri ='https://www.facebook.com/dialog/oauth?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&state={state}&scope={scopes}'.format(
            client_id=client_id, 
            redirect_uri=redirect_uri, 
            state='samdk', 
            scopes='email')

facebook = OAuth2Service(
    client_id=client_id,
    client_secret=client_secret,
    name='facebook',
    authorize_url='https://graph.facebook.com/oauth/authorize',
    access_token_url='https://graph.facebook.com/oauth/access_token',
    base_url='https://graph.facebook.com/')




def myconverter(o):
    if isinstance(o, datetime):
        return o.__str__()


def get_user(user, token_info):
    users = crud.get(User, limit=100)
    return list(filter(lambda u: u.get('id') == user, users)) + list(filter(lambda u: u.get('id') != user, users))

def get_messages(user, token_info):  

    last_mesasges = Session.query(Message.uid, func.max(Message.tms).label('last_tms')).\
        group_by(Message.uid).\
        subquery()

    tags_per_message = Session.query( Message.uid, Message.id, func.array_agg(Tag.name).label('tag_names') ).\
        join(Tag, Message.tags).\
        group_by(Message.uid, Message.id).\
        subquery()

    query = Session.query( last_mesasges.c.uid, tags_per_message.c.id, tags_per_message.c.tag_names, last_mesasges.c.last_tms, User.name, User.avatar, Message.content ).\
        join( Message, last_mesasges.c.last_tms == Message.tms ).\
        join( tags_per_message, Message.id == tags_per_message.c.id ).\
        join( User, last_mesasges.c.uid == User.id ).\
        order_by( last_mesasges.c.last_tms )

    items = []

    for u in query:
        items.append({
            'user_id': u.uid,
            'message_id': u.id, 
            'user_name': u.name,
            'avatar': u.avatar,
            'content': u.content,
            'tms': u.last_tms,
            'tag_names': u.tag_names,
        })

    return items

def get_host(user, token_info):  

    tags_per_message = Session.query( Message.uid, Message.id, func.array_agg(Tag.name).label('tag_names') ).\
        join(Tag, Message.tags).\
        group_by(Message.uid, Message.id).\
        subquery()

    query = Session.query( Message.id, Message.content, Message.tms, tags_per_message.c.tag_names ).\
        join( tags_per_message, Message.id == tags_per_message.c.id ).\
        filter(Message.uid == user ).\
        order_by( desc(Message.tms) )

    items = []

    for u in query:
        items.append({
            'user_id': user,
            'message_id': u.id, 
            'content': u.content,
            'tms': u.tms,
            'tag_names': u.tag_names,
        })

    return items


def create_message(user, token_info):
    request = connexion.request.get_json()


    instance = Message( content=request.get('content') )
    user = Session.query(User).filter(User.id == user ).first()
    instance.user = user

    tag_ids = request.get('tag_ids')
    if tag_ids is not None:
        tags = Session.query(Tag).filter(Tag.id.in_(tag_ids)).all()
        instance.tags = tags

    try:
        Session.add(instance)
        Session.commit()
        return instance.to_dict(), 201
    except Exception as err:
        print(err)
        logging.debug('Exception:post_id:{}'.format(err))
    return NoContent, 400


def get_tags(user, token_info):  
    tags = Session.query(Tag).all()
    items = []
    for u in tags:
        items.append({
            'id': u.id,
            'name': u.name, 
        })
    return items

def authorize():
    return redirect(request_uri)

def callback(code):
    if code is None:
        return redirect('foobar://error?message=code')
    social_id, username, email, picture_url, access_token = get_payload(code)
    if social_id is None:
        return redirect('foobar://error?message=social_id')

    users = crud.get(User, limit=1, social_id=social_id)
    user_id = None
    if len(users) > 0:
        user_id = users[0].get('id')
    if len(users)==0:
        result = User(
            social_id = social_id, 
            name = username, 
            email = email, 
            karma = 1.0
            )
        try:
            result.save()
            user_id = result.id
        except Exception as err:
            print('Exception:user_create:{}'.format(err))

    if(user_id is None): 
        return redirect('foobar://success')

    auth_token = generate_token(user_id).decode("utf-8")

    crud.put(User, id=user_id, user={
        'avatar': picture_url, 
        'facebook_authorization_code': code,
        'facebook_access_token': access_token,
        'auth_token': auth_token
    })

    #user_count = len(crud.get(User, limit=None, email=None))
    return redirect('foobar://success?token='+auth_token)

def get_payload(code):
    def decode_json(payload):
        return json.loads(payload.decode('utf-8'))

    oauth_session = facebook.get_auth_session(
        data={'code': code,
              'grant_type': 'authorization_code',
              'redirect_uri': redirect_uri},
        decoder=decode_json
    )
    me = oauth_session.get('me?fields=id,email,picture.width(320)').json()
    picture_url = 'https://graph.facebook.com/'+ me['id'] +'/picture?width=320'

    return (
        'facebook$' + me['id'],
        me.get('email').split('@')[0],  # Facebook does not provide username, so the email's user is used instead
        me.get('email'),
        picture_url,
        oauth_session.access_token
    )

def generate_token(user_id):
    timestamp = _current_timestamp()
    payload = {
        "iss": JWT_ISSUER,
        "iat": int(timestamp),
        "exp": int(timestamp + JWT_LIFETIME_SECONDS),
        "sub": user_id,
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.exceptions.ExpiredSignatureError as e:
        six.raise_from(Unauthorized, e)
    except BaseException as e:
        six.raise_from(Unauthorized, e)

def _current_timestamp() -> int:
    return int(time.time())

# @socketio.on('create')
# def on_create(data):
#     """Create a game lobby"""
#     gm = game.Info(
#         size=data['size'],
#         teams=data['teams'],
#         dictionary=data['dictionary'])
#     room = gm.game_id
#     ROOMS[room] = gm
#     join_room(room)
#     emit('join_room', {'room': room})


# @socketio.on('join')
# def on_join(data):
#     """Join a game lobby"""
#     # username = data['username']
#     room = data['room']
#     if room in ROOMS:
#         # add player and rebroadcast game object
#         # rooms[room].add_player(username)
#         join_room(room)
#         send(ROOMS[room].to_json(), room=room)
#     else:
#         emit('error', {'error': 'Unable to join room. Room does not exist.'})

# @socketio.on('flip_card')
# def on_flip_card(data):
#     """flip card and rebroadcast game object"""
#     room = data['room']
#     card = data['card']
#     ROOMS[room].flip_card(card)
#     send(ROOMS[room].to_json(), room=room)





app = connexion.App(__name__)
app.add_api('openapi.yml')

flask_app = app.app
socketio = SocketIO(flask_app, logger=True)

@app.route('/')
def index():
    socketio.emit('broadcast', {'data': 'index'})

    return render_template('index.html')

@socketio.on('tap_up')
def tap_up(x, y):
    jwt = decode_token(request.args.get('auth'))
    user_id = jwt.get('sub')
    emit('broadcast', {'data': {'user_id': user_id, 'position':{'x': x, 'y': y}}}, broadcast=True)

@socketio.on('spin')
def spin(corner, velocity):
    jwt = decode_token(request.args.get('auth'))
    user_id = jwt.get('sub')
    emit('spincast', {'data': {'user_id': user_id, 'position':{'corner': corner, 'velocity': velocity}}}, broadcast=True)

@socketio.on('tap_down')
def tap_down(x, y):
    print('tap')
    # jwt = decode_token(request.args.get('auth'))
    # user_id = jwt.get('sub')
    # emit('broadcast', {'data': {'user_id': user_id, 'position':{'x': x, 'y': y}}}, broadcast=True)

@socketio.on('connect')
def test_connect():
    print('Client connected')
    emit('broadcast', {'data': 'Connected'})

@socketio.on('disconnect')
def test_disconnect():
    print('Client disconnected')


if __name__ == '__main__':
    port = os.environ.get('APP_PORT', 8080)
    #DbModel.metadata.drop_all(bind=engine)
    DbModel.metadata.create_all(bind=engine)
    socketio.run(flask_app, host='0.0.0.0',  debug=True, port=int(port))



