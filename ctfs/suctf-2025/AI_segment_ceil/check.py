from PIL import Image
import os
import numpy as np
import io
import base64
import random
import time

from model import DDPM
import torch
model = torch.load("outputs/model_40.pt")

def to_tensor(image):
    return torch.tensor(np.array(image)).permute(2, 0, 1).float() / 255.0

def get_label(img):
    img = to_tensor(img).to('cuda')
    img = img.unsqueeze(0)
    pred = model(img)
    pred = pred.squeeze(0)
    pred = pred > 0.55
    pred = pred.int()
    pred = pred * 255
    pred = pred.clamp(0, 255)
    pred = pred.permute(1, 2, 0).cpu().numpy() # (512, 512, 1)
    pred = np.repeat(pred, 3, axis=2)
    return Image.fromarray(pred.astype(np.uint8))



# 指定输入和输出文件夹路径
image_folder = 'train/image'
label_folder = 'train/label'

# 列出所有 JPG 文件
png_files = [f for f in os.listdir(label_folder) if f.lower().endswith('.png')]
png_files = random.sample(png_files, min(10, len(png_files)))

png_files = ['23.png']

win = True

def add_uniform_noise(image):
    image = np.array(image)
    w, h, c = image.shape
    for i in range(w):
        for j in range(h):
            for k in range(c):
                image[i][j][k] += random.randint(-3, 3)
    return Image.fromarray(image)

def filter_image(image):
    image = np.array(image)
    w, h, c = image.shape
    for i in range(w):
        for j in range(h):
            if image[i][j][0] < 100 and image[i][j][1] < 100 and image[i][j][2] < 100:
                image[i][j] = [0, 0, 0]
            else:
                image[i][j] = [255, 255, 255]
    return Image.fromarray(image)


# 读取每个 JPG 文件，处理并保存
for png_file in png_files:
    print('png_file:', png_file)
    label_path = os.path.join(label_folder, png_file)  # 构建完整路径
    image_path = os.path.join(image_folder, png_file)
    label = Image.open(label_path).convert('RGB')  # 读取图片
    w, h = label.size
    label = np.array(label)
    image = Image.open(image_path).convert('RGB')
    image = add_uniform_noise(image)
    # image.show()
    # get_canny(image).show()
    # buffered = io.BytesIO()
    # image.save(buffered, format="PNG")
    # base64_string = base64.b64encode(buffered.getvalue()).decode('utf-8')
    # print('image:',base64_string)

    # start_time = time.time()
    # base64_string = input("can you help me segment the image:")
    # end_time = time.time()
    # if end_time - start_time > 2:
    #     win = False
    #     break
    # image_bytes = base64.b64decode(base64_string)
    # buffered = io.BytesIO(image_bytes)
    # predict = Image.open(buffered)
    # predict = filter_image(image)
    predict = get_label(image)
    # predict.show()
    predict = np.array(predict)

    correct = 0
    num = 0

    test_num = 0

    for i in range(h):
        for j in range(w):
            if label[i][j][0] == 0 and label[i][j][1] == 0 and label[i][j][2] == 0:
                num += 1
            if predict[i][j][0] == 0 and predict[i][j][1] == 0 and predict[i][j][2] == 0:
                num += 1
                test_num += 1
            if label[i][j][0] == 0 and label[i][j][1] == 0 and label[i][j][2] == 0 and predict[i][j][0] == 0 and predict[i][j][1] == 0 and predict[i][j][2] == 0:
                correct += 1

    print((2*correct/num)*100, test_num, correct, num-test_num)
    if (2*correct/num)*100 < 78:
        win = False
        break

if win :
    print('SUCTF{win}')