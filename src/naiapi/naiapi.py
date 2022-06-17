import requests
import json
from hashlib import blake2b
from passlib.hash import argon2
import base64
import nacl.secret
import nacl.utils

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

    def get_custom_modules(get_by_id = True):
        response = NAIApi.__get_objects__("aimodules")
        if response is not None:
            modules = []
            for obj in response:
                meta = obj["meta"]
                data = base64.b64decode(obj["data"])
                nonce = data[:24]
                sdata = data[24:]
                module = json.loads(NAIApi.__decode_secret_box__(sdata, nonce, bytes(NAIApi.__keystore__[meta])).decode('UTF-8'))
                modules.append({
                                    "id": module["id"],
                                    "name": module["name"],
                                    "description": module["description"]
                                })
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
        print(params)
        if get_stream:
            api_url = NAIApi.__base_url__ + "ai/generate-stream"
        else:
            api_url = NAIApi.__base_url__ + "ai/generate"
        body = {
            "input": input,
            "model": MODELS[model],
            "parameters": params.export()
        }
        response = requests.post(api_url, json=body, headers=NAIApi.__header__)
        ex = response_code_exception(response)
        if ex is None:
            return response.json()
        else:
            raise ex

EUTERPE_BAD_WORDS_IDS = [[58],[60],[90],[92],[685],[1391],[1782],[2361],[3693],[4083],[4357],[4895],[5512],[5974],[7131],[8183],[8351],[8762],[8964],[8973],[9063],[11208],[11709],[11907],[11919],[12878],[12962],[13018],[13412],[14631],[14692],[14980],[15090],[15437],[16151],[16410],[16589],[17241],[17414],[17635],[17816],[17912],[18083],[18161],[18477],[19629],[19779],[19953],[20520],[20598],[20662],[20740],[21476],[21737],[22133],[22241],[22345],[22935],[23330],[23785],[23834],[23884],[25295],[25597],[25719],[25787],[25915],[26076],[26358],[26398],[26894],[26933],[27007],[27422],[28013],[29164],[29225],[29342],[29565],[29795],[30072],[30109],[30138],[30866],[31161],[31478],[32092],[32239],[32509],[33116],[33250],[33761],[34171],[34758],[34949],[35944],[36338],[36463],[36563],[36786],[36796],[36937],[37250],[37913],[37981],[38165],[38362],[38381],[38430],[38892],[39850],[39893],[41832],[41888],[42535],[42669],[42785],[42924],[43839],[44438],[44587],[44926],[45144],[45297],[46110],[46570],[46581],[46956],[47175],[47182],[47527],[47715],[48600],[48683],[48688],[48874],[48999],[49074],[49082],[49146],[49946],[10221],[4841],[1427],[2602,834],[29343],[37405],[35780],[2602],[50256]]
KRAKE_BAD_WORDS_IDS = [[60],[62],[544],[683],[696],[880],[905],[1008],[1019],[1084],[1092],[1181],[1184],[1254],[1447],[1570],[1656],[2194],[2470],[2479],[2498],[2947],[3138],[3291],[3455],[3725],[3851],[3891],[3921],[3951],[4207],[4299],[4622],[4681],[5013],[5032],[5180],[5218],[5290],[5413],[5456],[5709],[5749],[5774],[6038],[6257],[6334],[6660],[6904],[7082],[7086],[7254],[7444],[7748],[8001],[8088],[8168],[8562],[8605],[8795],[8850],[9014],[9102],[9259],[9318],[9336],[9502],[9686],[9793],[9855],[9899],[9955],[10148],[10174],[10943],[11326],[11337],[11661],[12004],[12084],[12159],[12520],[12977],[13380],[13488],[13663],[13811],[13976],[14412],[14598],[14767],[15640],[15707],[15775],[15830],[16079],[16354],[16369],[16445],[16595],[16614],[16731],[16943],[17278],[17281],[17548],[17555],[17981],[18022],[18095],[18297],[18413],[18736],[18772],[18990],[19181],[20095],[20197],[20481],[20629],[20871],[20879],[20924],[20977],[21375],[21382],[21391],[21687],[21810],[21828],[21938],[22367],[22372],[22734],[23405],[23505],[23734],[23741],[23781],[24237],[24254],[24345],[24430],[25416],[25896],[26119],[26635],[26842],[26991],[26997],[27075],[27114],[27468],[27501],[27618],[27655],[27720],[27829],[28052],[28118],[28231],[28532],[28571],[28591],[28653],[29013],[29547],[29650],[29925],[30522],[30537],[30996],[31011],[31053],[31096],[31148],[31258],[31350],[31379],[31422],[31789],[31830],[32214],[32666],[32871],[33094],[33376],[33440],[33805],[34368],[34398],[34417],[34418],[34419],[34476],[34494],[34607],[34758],[34761],[34904],[34993],[35117],[35138],[35237],[35487],[35830],[35869],[36033],[36134],[36320],[36399],[36487],[36586],[36676],[36692],[36786],[37077],[37594],[37596],[37786],[37982],[38475],[38791],[39083],[39258],[39487],[39822],[40116],[40125],[41000],[41018],[41256],[41305],[41361],[41447],[41449],[41512],[41604],[42041],[42274],[42368],[42696],[42767],[42804],[42854],[42944],[42989],[43134],[43144],[43189],[43521],[43782],[44082],[44162],[44270],[44308],[44479],[44524],[44965],[45114],[45301],[45382],[45443],[45472],[45488],[45507],[45564],[45662],[46265],[46267],[46275],[46295],[46462],[46468],[46576],[46694],[47093],[47384],[47389],[47446],[47552],[47686],[47744],[47916],[48064],[48167],[48392],[48471],[48664],[48701],[49021],[49193],[49236],[49550],[49694],[49806],[49824],[50001],[50256],[0],[1]]


MODELS = {
    "Euterpe": "euterpe-v2",
    "Krake": "krake-v2"
}

PRESETS = {
    "Euterpe": ["genesis",
                "basic_coherence",
                "ouroboros",
                "ace_of_spades",
                "moonlit_chronicler",
                "fandango",
                "all-nighter",
                "low_rider",
                "morpho",
                "pro_writer"],
    "Krake": ["blue_lighter",
              "redjack",
              "calypso",
              "blue_adder",
              "reverie",
              "20BC+",
              "calibrated",
              "iris",
              "krait"]
}

MODULES = [
	"general_crossgenre",
	"theme_textadventure",
	"style_algernonblackwood",
	"style_arthurconandoyle",
	"style_edgarallanpoe",
	"style_hplovecraft",
	"style_shridanlefanu",
	"style_julesverne",
	"theme_19thcenturyromance",
	"theme_actionarcheology",
	"theme_animalfiction",
	"theme_airships",
	"theme_ai",
	"theme_childrens",
	"theme_christmas",
	"theme_comedicfantasy",
	"theme_cyberpunk",
	"theme_darkfantasy",
	"theme_dragons",
	"theme_egypt",
	"theme_feudaljapan",
	"theme_generalfantasy",
	"theme_history",
	"theme_horror",
	"theme_huntergatherer",
	"theme_magicacademy",
	"theme_libraries",
	"theme_litrpg",
	"theme_mars",
	"theme_medieval",
	"theme_militaryscifi",
	"theme_mystery",
	"theme_naval",
	"theme_philosophy",
	"theme_pirates",
	"theme_poeticfantasy",
	"theme_postapocalyptic",
	"theme_rats",
	"theme_romanempire",
	"theme_sciencefantasy",
	"theme_spaceopera",
	"theme_romanceofthreekingdoms",
	"theme_superheroes",
	"theme_travel",
	"theme_valentines",
	"theme_vikings",
	"theme_urbanfantasy",
	"theme_westernromance",
	"inspiration_crabsnailandmonkey",
	"inspiration_mercantilewolfgirlromance",
	"inspiration_nervegear",
	"inspiration_thronewars",
	"inspiration_witchatlevelcap"
]

ORDER_IDS = {
    'temperature': 0,
    'top_k': 1,
    'top_p': 2,
    'tfs': 3,
    'top_a': 4,
    'typical_p': 5
}

class Params:
    def __init__(self,
                prefix="vanilla",
                temperature=None,
                max_length=40,
                context_length=None,
                min_length=1,
                top_k=None,
                top_p=None,
                top_a=None,
                typical_p=None,
                tail_free_sampling=None,
                repetition_penalty=None,
                repetition_penalty_slope=None,
                repetition_penalty_frequency=None,
                repetition_penalty_presence=None,
                repetition_penalty_whitelist=None,
                repetition_penalty_range=None,
                bad_words_ids=EUTERPE_BAD_WORDS_IDS,
                logit_bias=None,
                logit_bias_groups=None,
                ban_brackets=None,
                use_cache=False,
                use_string=True,
                return_full_text=False,
                trim_spaces=None,
                output_nonzero_probs=None,
                next_word=None,
                num_logprobs=None,
                generate_until_sentence=True,
                order=None):
        self.temperature = temperature        
        self.top_k = top_k        
        self.top_p = top_p        
        self.top_a = top_a        
        self.typical_p = typical_p        
        self.tail_free_sampling = tail_free_sampling        
        self.repetition_penalty = repetition_penalty        
        self.repetition_penalty_slope = repetition_penalty_slope        
        self.repetition_penalty_frequency = repetition_penalty_frequency        
        self.repetition_penalty_presence = repetition_penalty_presence        
        self.repetition_penalty_whitelist = repetition_penalty_whitelist        
        self.repetition_penalty_range = repetition_penalty_range        
        self.logit_bias = logit_bias        
        self.logit_bias_groups = logit_bias_groups        
        self.ban_brackets = ban_brackets        
        self.trim_spaces = trim_spaces        
        self.output_nonzero_probs = output_nonzero_probs        
        self.next_word = next_word        
        self.num_logprobs = num_logprobs
        self.context_length = context_length
        self.max_length = max_length
        self.min_length = min_length
        self.use_cache = use_cache
        self.use_string = use_string
        self.return_full_text = return_full_text
        self.prefix = prefix
        self.generate_until_sentence = generate_until_sentence
        self.order = order
        self.bad_words_ids = bad_words_ids

    def preset(preset):
        if preset == "genesis":
            return Params(bad_words_ids=EUTERPE_BAD_WORDS_IDS,
                        order=[2, 1, 3, 0],
                        repetition_penalty=1.148125,
                        repetition_penalty_frequency=0,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=2048,
                        repetition_penalty_slope=0.09,
                        tail_free_sampling=0.975,
                        temperature=0.63,
                        top_k=0,
                        top_p=0.975)
        if preset == "basic_coherence":
            return Params(bad_words_ids=EUTERPE_BAD_WORDS_IDS,
                        order=[0, 1, 2, 3],
                        repetition_penalty=1.15375,
                        repetition_penalty_frequency=0,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=2048,
                        repetition_penalty_slope=0.33,
                        tail_free_sampling=0.87,
                        temperature=0.585,
                        top_k=0,
                        top_p=1)
        if preset == "ouroboros":
            return Params(bad_words_ids=EUTERPE_BAD_WORDS_IDS,
                        order=[1, 0, 3],
                        repetition_penalty=1.087375,
                        repetition_penalty_frequency=0,
                        repetition_penalty_range=404,
                        repetition_penalty_slope=0.84,
                        tail_free_sampling=0.925,
                        temperature=1.07,
                        top_k=264)
        if preset == "ace_of_spades":
            return Params(bad_words_ids=EUTERPE_BAD_WORDS_IDS,
                        order=[3, 2, 1, 0],
                        repetition_penalty=1.13125,
                        repetition_penalty_frequency=0,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=2048,
                        repetition_penalty_slope=7.02,
                        tail_free_sampling=0.8,
                        temperature=1.15,
                        top_k=0,
                        top_p=0.95)
        if preset == "moonlit_chronicler":
            return Params(bad_words_ids=EUTERPE_BAD_WORDS_IDS,
                        order=[1, 5, 4, 3, 0],
                        repetition_penalty=1.080625,
                        repetition_penalty_frequency=0,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=512,
                        repetition_penalty_slope=0.36,
                        tail_free_sampling=0.802,
                        temperature=1.25,
                        top_a=0.782,
                        top_k=300,
                        typical_p=0.95)
        if preset == "fandango":
            return Params(bad_words_ids=EUTERPE_BAD_WORDS_IDS,
                        order=[2, 1, 3, 0],
                        repetition_penalty=1.09375,
                        repetition_penalty_frequency=0,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=2048,
                        repetition_penalty_slope=0.09,
                        tail_free_sampling=1,
                        temperature=0.86,
                        top_k=20,
                        top_p=0.95)
        if preset == "all-nighter":
            return Params(bad_words_ids=EUTERPE_BAD_WORDS_IDS,
                        order=[1, 0, 3],
                        repetition_penalty=1.10245,
                        repetition_penalty_frequency=0.01,
                        repetition_penalty_range=400,
                        repetition_penalty_slope=0.33,
                        tail_free_sampling=0.836,
                        temperature=1.33,
                        top_k=13)
        if preset == "low_rider":
            return Params(bad_words_ids=EUTERPE_BAD_WORDS_IDS,
                        order=[2, 1, 3, 0],
                        repetition_penalty=1.1245,
                        repetition_penalty_frequency=0.013,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=2048,
                        repetition_penalty_slope=0.18,
                        tail_free_sampling=0.94,
                        temperature=0.94,
                        top_k=12,
                        top_p=1)
        if preset == "morpho":
            return Params(bad_words_ids=EUTERPE_BAD_WORDS_IDS,
                        order=[0],
                        repetition_penalty=1,
                        repetition_penalty_frequency=0.1,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=2048,
                        temperature=0.6889)
        if preset == "pro_writer":
            return Params(bad_words_ids=EUTERPE_BAD_WORDS_IDS,
                        order=[3, 0],
                        repetition_penalty=1.2975249999999998,
                        repetition_penalty_frequency=0,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=2048,
                        repetition_penalty_slope=0.09,
                        tail_free_sampling=0.688,
                        temperature=1.348)
        if preset == "blue_lighter":
            return Params(bad_words_ids=KRAKE_BAD_WORDS_IDS,
                        order=[3, 4, 5, 2, 0],
                        repetition_penalty=1.05,
                        repetition_penalty_frequency=0,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=560,
                        tail_free_sampling=0.937,
                        temperature=1.33,
                        top_a=0.085,
                        top_p=0.88,
                        typical_p=0.965)
        if preset == "redjack":
            return Params(bad_words_ids=KRAKE_BAD_WORDS_IDS,
                        order=[3, 2, 0],
                        repetition_penalty=1.0075,
                        repetition_penalty_frequency=0.025,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=2048,
                        repetition_penalty_slope=4,
                        tail_free_sampling=0.92,
                        temperature=1.1,
                        top_p=0.96)
        if preset == "calypso":
            return Params(bad_words_ids=KRAKE_BAD_WORDS_IDS,
                        order=[2, 1, 3, 0, 4, 5],
                        repetition_penalty=1.075,
                        repetition_penalty_frequency=0,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=2048,
                        repetition_penalty_slope=0.09,
                        tail_free_sampling=0.95,
                        temperature=1.1,
                        top_a=0.15,
                        top_k=10,
                        top_p=0.95,
                        typical_p=0.95)
        if preset == "blue_adder":
            return Params(bad_words_ids=KRAKE_BAD_WORDS_IDS,
                        order=[5, 3, 0, 4],
                        repetition_penalty=1.02325,
                        repetition_penalty_frequency=0,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=496,
                        repetition_penalty_slope=0.72,
                        tail_free_sampling=0.991,
                        temperature=1.01,
                        top_a=0.06,
                        typical_p=0.996)
        if preset == "reverie":
            return Params(bad_words_ids=KRAKE_BAD_WORDS_IDS,
                        order=[3, 5, 4, 2, 0, 1],
                        repetition_penalty=1.0025,
                        repetition_penalty_frequency=0,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=2048,
                        tail_free_sampling=0.925,
                        top_a=0.12,
                        top_k=85,
                        top_p=0.985,
                        typical_p=0.85)
        if preset == "20BC+":
            return Params(bad_words_ids=KRAKE_BAD_WORDS_IDS,
                        order=[0, 1, 2, 3],
                        repetition_penalty=1.055,
                        repetition_penalty_frequency=0,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=2048,
                        repetition_penalty_slope=3.33,
                        tail_free_sampling=0.879,
                        temperature=0.58,
                        top_k=20,
                        top_p=1)
        if preset == "calibrated":
            return Params(bad_words_ids=KRAKE_BAD_WORDS_IDS,
                        order=[0, 5],
                        repetition_penalty=1.036,
                        repetition_penalty_frequency=0,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=2048,
                        repetition_penalty_slope=3.33,
                        temperature=0.34,
                        typical_p=0.975)
        if preset == "iris":
            return Params(bad_words_ids=KRAKE_BAD_WORDS_IDS,
                        order=[3, 0, 5],
                        repetition_penalty=1,
                        repetition_penalty_frequency=0,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=2048,
                        tail_free_sampling=0.97,
                        temperature=2.5,
                        typical_p=0.9566)
        if preset == "krait":
            return Params(bad_words_ids=KRAKE_BAD_WORDS_IDS,
                        order=[1, 4, 0, 3, 5],
                        repetition_penalty=1.0236,
                        repetition_penalty_frequency=0,
                        repetition_penalty_presence=0,
                        repetition_penalty_range=610,
                        repetition_penalty_slope=0.85,
                        tail_free_sampling=0.997,
                        temperature=0.9,
                        top_a=0.072,
                        top_k=1000,
                        typical_p=0.98)
        return None

    def update(self, p):
        if p.temperature is not None:
            self.temperature = p.temperature
        if p.max_length is not None:
            self.max_length = p.max_length
        if p.context_length is not None:
            self.context_length = p.context_length
        if p.min_length is not None:
            self.min_length = p.min_length
        if p.top_k is not None:
            self.top_k = p.top_k
        if p.top_p is not None:
            self.top_p = p.top_p
        if p.top_a is not None:
            self.top_a = p.top_a
        if p.typical_p is not None:
            self.typical_p = p.typical_p
        if p.tail_free_sampling is not None:
            self.tail_free_sampling = p.tail_free_sampling
        if p.repetition_penalty is not None:
            self.repetition_penalty = p.repetition_penalty
        if p.repetition_penalty_slope is not None:
            self.repetition_penalty_slope = p.repetition_penalty_slope
        if p.repetition_penalty_frequency is not None:
            self.repetition_penalty_frequency = p.repetition_penalty_frequency
        if p.repetition_penalty_presence is not None:
            self.repetition_penalty_presence = p.repetition_penalty_presence
        if p.repetition_penalty_whitelist is not None:
            self.repetition_penalty_whitelist = p.repetition_penalty_whitelist
        if p.repetition_penalty_range is not None:
            self.repetition_penalty_range = p.repetition_penalty_range
        if p.logit_bias is not None:
            self.logit_bias = p.logit_bias
        if p.logit_bias_groups is not None:
            self.logit_bias_groups = p.logit_bias_groups
        if p.ban_brackets is not None:
            self.ban_brackets = p.ban_brackets
        if p.trim_spaces is not None:
            self.trim_spaces = p.trim_spaces
        if p.output_nonzero_probs is not None:
            self.output_nonzero_probs = p.output_nonzero_probs
        if p.next_word is not None:
            self.next_word = p.next_word
        if p.num_logprobs is not None:
            self.num_logprobs = p.num_logprobs
        if p.bad_words_ids is not None:
            self.bad_words_ids = p.bad_words_ids
        if p.use_cache is not None:
            self.use_cache = p.use_cache
        if p.use_string is not None:
            self.use_string = p.use_string
        if p.return_full_text is not None:
            self.return_full_text = p.return_full_text
        if p.prefix is not None:
            self.prefix = p.prefix
        if p.generate_until_sentence is not None:
            self.generate_until_sentence = p.generate_until_sentence
        if p.order is not None:
            self.order = p.order
    
    def export(self):
        result = dict()
        if self.temperature is not None:
            result['temperature'] = self.temperature
        if self.max_length is not None:
            result['max_length'] = self.max_length
        if self.context_length is not None:
            result['context_length'] = self.context_length
        if self.min_length is not None:
            result['min_length'] = self.min_length
        if self.top_k is not None:
            result['top_k'] = self.top_k
        if self.top_p is not None:
            result['top_p'] = self.top_p
        if self.top_a is not None:
            result['top_a'] = self.top_a
        if self.typical_p is not None:
            result['typical_p'] = self.typical_p
        if self.tail_free_sampling is not None:
            result['tail_free_sampling'] = self.tail_free_sampling
        if self.repetition_penalty is not None:
            result['repetition_penalty'] = self.repetition_penalty
        if self.repetition_penalty_slope is not None:
            result['repetition_penalty_slope'] = self.repetition_penalty_slope
        if self.repetition_penalty_frequency is not None:
            result['repetition_penalty_frequency'] = self.repetition_penalty_frequency
        if self.repetition_penalty_presence is not None:
            result['repetition_penalty_presence'] = self.repetition_penalty_presence
        if self.repetition_penalty_whitelist is not None:
            result['repetition_penalty_whitelist'] = self.repetition_penalty_whitelist
        if self.repetition_penalty_range is not None:
            result['repetition_penalty_range'] = self.repetition_penalty_range
        if self.logit_bias is not None:
            result['logit_bias'] = self.logit_bias
        if self.logit_bias_groups is not None:
            result['logit_bias_groups'] = self.logit_bias_groups
        if self.ban_brackets is not None:
            result['ban_brackets'] = self.ban_brackets
        if self.trim_spaces is not None:
            result['trim_spaces'] = self.trim_spaces
        if self.output_nonzero_probs is not None:
            result['output_nonzero_probs'] = self.output_nonzero_probs
        if self.next_word is not None:
            result['next_word'] = self.next_word
        if self.num_logprobs is not None:
            result['num_logprobs'] = self.num_logprobs
        if self.bad_words_ids is not None:
            result['bad_words_ids'] = self.bad_words_ids
        if self.use_cache is not None:
            result['use_cache'] = self.use_cache
        if self.use_string is not None:
            result['use_string'] = self.use_string
        if self.return_full_text is not None:
            result['return_full_text'] = self.return_full_text
        if self.prefix is not None:
            result['prefix'] = self.prefix
        if self.generate_until_sentence is not None:
            result['generate_until_sentence'] = self.generate_until_sentence
        if self.order is not None:
            result['order'] = self.order
        return result

def response_code_exception(response):
    if response is None:
        return UnknownError("No response returned.")
    if response.status_code >= 200 and response.status_code < 300:
        return None
    
    msg = response.text
    if response.status_code >= 400 and response.status_code < 404:
        return ValidationError(msg)
    if response.status_code == 404:
        return NotFoundError(msg)
    if response.status_code == 409:
        return ConflictError(msg)
    return UnknownError(msg)

class ValidationError(Exception):
    pass

class NotFoundError(Exception):
    pass

class ConflictError(Exception):
    pass

class UnknownError(Exception):
    pass