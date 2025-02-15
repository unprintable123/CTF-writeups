from pwn import *
import torch
from PIL import Image
import os
import numpy as np
import io
import base64
import random
import time

from model import DDPM

model = torch.load("outputs/model_40.pt")

def to_tensor(image):
    return torch.tensor(np.array(image)).permute(2, 0, 1).float() / 255.0

def get_label(img):
    img = to_tensor(img).to('cuda')
    img = img.unsqueeze(0)
    pred = model(img)
    pred = pred.squeeze(0)
    pred = pred > 0.56
    pred = pred.int()
    pred = pred * 255
    pred = pred.clamp(0, 255)
    pred = pred.permute(1, 2, 0).cpu().numpy() # (512, 512, 1)
    pred = np.repeat(pred, 3, axis=2)
    return Image.fromarray(pred.astype(np.uint8))

# conn = process(["python", "server.py"])
# nc 1.95.34.240 10001
conn = remote("1.95.34.240", 10001)



for i in range(10):
    print("Round", i)
    conn.recvuntil(b"image:")
    b64_image = conn.recvline().strip().decode()
    image_bytes = base64.b64decode(b64_image)
    buffered = io.BytesIO(image_bytes)
    image = Image.open(buffered)
    image = np.array(image)

    pred = get_label(image)

    buffered = io.BytesIO()
    pred.save(buffered, format="PNG")
    b64_pred = base64.b64encode(buffered.getvalue()).decode('utf-8')

    conn.sendline(b64_pred.encode())
    conn.recvuntil(b"can you help me segment the image:")

conn.interactive()





