import requests
import json
import passlib
from hashlib import blake2b
from passlib.hash import argon2
import base64
import hmac
import nacl.secret
import nacl.utils
from defs import *
from exceptions import response_code_exception

class NAIApi:
    __base_url__ = "https://api.novelai.net/"
    __keys__ = None
    __token__ = None
    __header__ = None
    __keystore__ = None

    def load_saved_credentials(encryption_key, access_key, token):
        NAIApi.set_keys(encryption_key, access_key)
        NAIApi.set_token(token)
        NAIApi.get_keystore()

    def set_keys(encrypt, access):
        if NAIApi.__keys__ is None:
            NAIApi.__keys__ = dict()
        NAIApi.__keys__["encryption_key"] = encrypt
        NAIApi.__keys__["access_key"] = access
    
    def set_token(token):
        NAIApi.__token__ = token
        NAIApi.__header__ = {"Content-Type": "application/json",
            "Authorization": "Bearer " + NAIApi.__token__}

    def __get_keys__(email, pw):
        secret = pw[:6] + email
        secret2 = bytes(secret + "novelai_data_encryption_key", "utf-8")
        encoder = blake2b(digest_size=16)
        encoder.update(secret2)
        salt = encoder.digest()
        hash = argon2.using(salt=salt,
                        time_cost = 2,
                        memory_cost = int(2000000/1024),
                        parallelism = 1,
                        digest_size = 128).hash(pw)

        encryption_key = hash.split("$")[len(hash.split("$")) - 1].replace("/", "_").replace("+", "-")
        encoder = blake2b(digest_size=32)
        encoder.update(bytes(encryption_key, "utf-8"))
        encryption_key = encoder.digest()

        secret2 = bytes(secret + "novelai_data_access_key", "utf-8")
        encoder = blake2b(digest_size=16)
        encoder.update(secret2)
        salt = encoder.digest()
        hash = argon2.using(salt=salt,
                        time_cost = 2,
                        memory_cost = int(2000000/1024),
                        parallelism = 1,
                        checksum_size=64).hash(pw)

        access_key = hash.split("$")[len(hash.split("$")) - 1].replace("/", "_").replace("+", "-")[:64]
        NAIApi.set_keys(encryption_key, access_key)

    def login(email, pw):
        NAIApi.__get_keys__(email, pw)
        json = { "key": NAIApi.__keys__["access_key"] }
        api_url = NAIApi.__base_url__ + "user/login"
        response = requests.post(api_url, json=json)
        ex = response_code_exception(response)
        if ex is None:
            NAIApi.set_token(response.json()['accessToken'])
            NAIApi.get_keystore()
        else:
            raise ex

    def logout():
        NAIApi.__token__ = None
        NAIApi.__header__ = None
        NAIApi.__keys__ = None

    def is_logged_in():
        return (NAIApi.__keys__ and NAIApi.__token__)

    def get_keystore():
        api_url = NAIApi.__base_url__ + "user/keystore"
        response = requests.get(api_url, headers=NAIApi.__header__)
        ex = response_code_exception(response)
        if ex is None:
            response = response.json()
            data = base64.b64decode(response["keystore"])
            keystorestr = data.decode("UTF-8")
            keystoredict = json.loads(keystorestr)
            nonce = bytes(keystoredict["nonce"])
            sdata = bytes(keystoredict["sdata"])
            k = NAIApi.__decode_secret_box__(sdata, nonce, NAIApi.__keys__["encryption_key"])
            sb = nacl.secret.SecretBox(NAIApi.__keys__["encryption_key"])
            k = sb.decrypt(sdata, nonce)
            NAIApi.__keystore__ = json.loads(k.decode("UTF-8"))["keys"]
        else:
            raise ex

    def __get_objects__(t):
        if not NAIApi.is_logged_in():
            return None
        api_url = NAIApi.__base_url__ + "user/objects/" + t
        response = requests.get(api_url, headers=NAIApi.__header__)
        ex = response_code_exception(response)
        if ex is None:
            response = response.json()
            if "objects" in response:
                return response["objects"]
            else:
                return None
        else:
            raise ex

    def get_custom_modules():
        response = NAIApi.__get_objects__("aimodules")
        if response is not None:
            modules = {}
            for obj in response:
                meta = obj["meta"]
                data = base64.b64decode(obj["data"])
                nonce = data[:24]
                sdata = data[24:]
                module = json.loads(NAIApi.__decode_secret_box__(sdata, nonce, bytes(NAIApi.__keystore__[meta])).decode('UTF-8'))
                modules[module["id"]] = {
                    "name": module["name"],
                    "description": module["description"]
                }
            return modules
        else:
            return None

    def get_custom_presets():
        response = NAIApi.__get_objects__("presets")
        if response is not None:
            presets = {}
            for obj in response:
                data = json.loads(base64.b64decode(obj["data"]))
                if data["presetVersion"] == 3:
                    params = data["parameters"]
                    preset =  Params(temperature=params["temperature"],
                                    max_length=params["max_length"],
                                    min_length=params["min_length"],
                                    top_k=params["top_k"],
                                    top_p=params["top_p"],
                                    top_a=params["top_a"],
                                    typical_p=params["typical_p"],
                                    tail_free_sampling=params["tail_free_sampling"],
                                    repetition_penalty=params["repetition_penalty"],
                                    repetition_penalty_range=params["repetition_penalty_range"],
                                    repetition_penalty_slope=params["repetition_penalty_slope"],
                                    repetition_penalty_frequency=params["repetition_penalty_frequency"],
                                    repetition_penalty_presence=params["repetition_penalty_presence"])
                    order = []
                    for control in params["order"]:
                        if control["enabled"]:
                            order.append(ORDER_IDS[control["id"]])
                    preset.order = order
                    presets[data["id"]] = {
                        "name": data["name"],
                        "preset": preset
                    }
                else:
                    raise Exception("Preset version " + data["presetVersion"] + " is unsupported.")
            return presets
        else:
            return None

    def __decode_secret_box__(sdata, nonce, key):
        sb = nacl.secret.SecretBox(key)
        return sb.decrypt(sdata, nonce)

    def generate(input, model, preset=None, params=None, module=None, get_stream=False):
        model = model.capitalize()
        if preset is None and params is None:
            preset = PRESETS[model][0]
        if preset is not None:
            if preset not in PRESETS[model]:
                raise Exception
            p = Params.preset(preset)
            if params is not None:
                p.update(params)
            params = p
        if module is not None:
            if module.startswith(MODELS[model]):
                params.prefix = module
        if get_stream:
            api_url = NAIApi.__base_url__ + "ai/generate-stream"
        else:
            api_url = NAIApi.__base_url__ + "ai/generate"
        body = {
            "input": input,
            "model": MODELS[model],
            "parameters": params.__dict__
        }
        response = requests.post(api_url, json=body, headers=NAIApi.__header__)
        ex = response_code_exception(response)
        if ex is None:
            return response.json()
        else:
            raise ex