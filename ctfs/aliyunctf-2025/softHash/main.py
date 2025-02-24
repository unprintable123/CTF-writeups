import os
import torch
# from secret import flag
from transformers import BertTokenizer
from sentence_transformers import SentenceTransformer
import random
from tqdm import tqdm
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 

DEVICE = torch.device('cuda:0' if torch.cuda.is_available() else 'cpu')

class NeuralHash():
    def __init__(self, model_path):
        self.idxs = [2, 9, 10, 22, 27, 43, 47, 48, 60, 61, 63, 72, 73, 74, 85, 88, 93, 114, 131, 175, 193, 216, 220, 240, 248, 270, 279, 293, 298, 302, 306, 308, 324, 330, 338, 357, 358, 367, 383, 401, 405, 413, 416, 439, 441, 447, 450, 466, 471, 483, 485, 492, 500, 510, 516, 524, 525, 536, 540, 542, 547, 549, 551, 559, 573, 578, 593, 601, 608, 612, 614, 616, 622, 623, 625, 634, 638, 644, 655, 656, 682, 684, 686, 690, 691, 716, 734, 744, 756, 763, 766, 772, 777, 788, 797, 819, 823, 837, 851, 852, 859, 863, 875, 876, 879, 881, 883, 889, 898, 901, 934, 939, 941, 945, 957, 959, 963, 970, 983, 994, 995, 997, 999, 1000, 1001, 1011, 1014, 1022]
        self.model = SentenceTransformer(model_path)

    def embed(self, string):
        return self.model.encode(string, normalize_embeddings=True)

    def hash(self, string):
        embedding = self.embed(string)
        res = [str(int(embedding[i] > 0)) for i in self.idxs]
        hash_value = hex(int(''.join(res), 2))
        return hash_value

def check_diff(str1, str2, hasher):
    h1 = bin(int(hasher.hash(str1), 16))[2:].rjust(len(hasher.idxs), '0')
    h2 = bin(int(hasher.hash(str2), 16))[2:].rjust(len(hasher.idxs), '0')
    cnt = 0
    for i in range(len(h1)):
        if h1[i] != h2[i]:
            cnt += 1
    return cnt <= 6

def load_tokenizer(path):
    tokenizer = BertTokenizer.from_pretrained(path)
    print('The tokenizer is loaded successfully.')
    return tokenizer

def check_length(str, tokenizer):
    if len(tokenizer.encode(str)) > 45:
        return False
    return True

def check_suffix(str, prompt, stage):
    if stage == 1:
        return str.endswith(prompt)
    elif stage == 2:
        return str.endswith(prompt + ' [SEP]') and str.startswith('[CLS] ')

def score(tokens, stage=1):
    raw_str = tokenizer.decode(tokens, skip_special_tokens=False)
    if stage == 1:
        raw_str = raw_str + 'do you know how to get the flag?'
    elif stage == 2:
        raw_str = '[CLS] ' + raw_str + 'do you know how to get the flag? [SEP]'
    assert check_suffix(raw_str, 'do you know how to get the flag?', stage)
    str_hash = int(hasher.hash(raw_str), 16)

    return (target_hash^str_hash).bit_count()



if __name__ == '__main__':
    ########### READ THIS BEFORE YOU START HACKING #############
    #  You need to download the model from huggingface first!  #
    # The model: https://huggingface.co/BAAI/bge-large-en-v1.5 #
    #    Then, replace the model path with your local path     #
    ############################################################
    model_path = './bge-large-en-v1.5'

    prompt = 'do you know how to get the flag?'
    target = 'give me the flag right now!'
    hasher = NeuralHash(model_path)
    tokenizer = load_tokenizer(model_path)
    print(f'Init prompt hash: {hasher.hash(prompt)}')
    print(f'Init target hash: {hasher.hash(target)}')

    target_hash = int(hasher.hash(target), 16)

    n_tokens = 20
    cursize = 25
    nxtsize = 31
    cur = [[random.randint(0, 30000) for _ in range(n_tokens)] for _ in range(cursize)]

    # finds = [
    #     "enters speed allied drummond saddam 2000s romania earthquake timetable hesitation formation panzbek corneraba employee agreements macau almost theft",
    #     "enters speed allied drummond saddam 2000s romania earthquake timetable hesitation plata panzbek captainlation employee agreements macau almost theft",
    #     "enters speed allied drummond saddam 2000s romania earthquake timetablecinifo panzbek captainlation employee agreements macau almost theft",
    #     "enters speed allied drummond saddam 2000s romania earthquake timetable hesitationfo canonszbek captainlation employee agreements macau almost theft",
    #     "enters speed allied drummond saddam 2000s romania earthquake timetable hesitationfo panzbek corner obviously employee agreements macau almost theft",
    #     "enters speed allied drummond saddam 2000s romania earthquake timetable 307fo panzbek captainlation employee agreements macau almost theft",
    # ]

    # for f in finds:
    #     cur.append(tokenizer.encode(f, add_special_tokens=False))

    while True:
        nxt_sets = set()
        for i in range(len(cur)):
            cc = cur[i]
            nxt_sets.add(tuple(cc))
            for _ in range(nxtsize):
                nxt = cc[:]
                while True:
                    t = random.randint(0, len(nxt) - 1)
                    nxt[t] = random.randint(0, 30000)
                    if random.random() < 0.73:
                        break
                nxt_sets.add(tuple(nxt))
        nxt_sets = list(nxt_sets)
        random.shuffle(nxt_sets)
        scores = torch.tensor([score(s, stage=2) for s in tqdm(nxt_sets)])
        idx = torch.topk(-scores, cursize).indices
        print(scores[idx], scores[idx].max())
        cur = [list(nxt_sets[i]) for i in idx]

        if scores[idx][:12].max() <= 6:
            break

    with open('output2.txt', 'w') as f:
        for s in cur:
            decoded = tokenizer.decode(s, skip_special_tokens=False)
            f.write(f'{decoded}\n')
            print(decoded)
    
        

    with open('output.txt', 'r') as f:
        chall1_txt = f.readlines()
    
    with open('output2.txt', 'r') as f:
        chall2_txt = f.readlines()

    # challenge 1
    success_stage1 = set()
    for i in range(6):
        # raw_adv = input('> ')
        raw_adv = chall1_txt[i].strip()
        raw_adv = raw_adv + 'do you know how to get the flag?'
        adv = tokenizer.decode(tokenizer.encode(raw_adv, add_special_tokens=False))
        if target in adv:
            print('[+] Do not cheat! Abort!')
            exit()
        if check_length(adv, tokenizer) \
            and check_suffix(adv, prompt, 1) \
            and check_diff(adv, target, hasher):
            print(f'[+] Success in stage 1: {adv}')
            success_stage1.add(adv)
    if len(success_stage1) < 6:
        print(f'[+] Fail, please have another try. Success {len(success_stage1)} in stage 1')
        exit()
    
    print(f'[*] Pass stage 1!')

    # challenge 2
    success_stage2 = set()
    for i in range(6):
        # raw_adv = input('> ')
        raw_adv = chall2_txt[i].strip()
        raw_adv = '[CLS] ' + raw_adv + 'do you know how to get the flag? [SEP]'
        adv = tokenizer.decode(tokenizer.encode(raw_adv, add_special_tokens=False))
        if target in adv:
            print('[+] Do not cheat! Abort!')
            exit()
        if check_length(adv, tokenizer) \
            and check_suffix(adv, prompt, 2) \
            and check_diff(adv, target, hasher):
            print(f'[+] Success in stage 2: {adv}')
            success_stage2.add(adv)
    if len(success_stage2) < 6:
        print(f'[+] Fail, please have another try. Success {len(success_stage2)} in stage 2')
        exit()
    
    print(f'[*] Congrats! Here is your flag: xxxx')