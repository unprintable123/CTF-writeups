from model import DDPM
from PIL import Image
import os
import torch
import numpy as np
import random
from tqdm import tqdm

image_folder = 'train/image'
label_folder = 'train/label'

os.makedirs('outputs', exist_ok=True)

png_files = [f for f in os.listdir(label_folder) if f.lower().endswith('.png')]

dataset = []

def to_tensor(image):
    return torch.tensor(np.array(image)).permute(2, 0, 1).float() / 255.0

for png_file in png_files:
    label_path = os.path.join(label_folder, png_file)
    image_path = os.path.join(image_folder, png_file)
    label = Image.open(label_path).convert('RGB')
    image = Image.open(image_path).convert('RGB')
    label = to_tensor(label)
    label = label.mean(dim=0, keepdim=True).to('cuda')
    image = to_tensor(image).to('cuda')

    dataset.append((image, label, png_file))

random.shuffle(dataset)

train_dataset = dataset[:-1]
val_dataset = dataset[-1:]
print(val_dataset[0][2])


model = DDPM().to('cuda')

optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
criterion = torch.nn.MSELoss()

for epoch in range(100):
    model.train()
    random.shuffle(train_dataset)
    for i in tqdm(range(len(train_dataset))):
        image, label, _ = train_dataset[i]
        optimizer.zero_grad()
        image = image.unsqueeze(0)
        image = image + torch.randn_like(image) * 0.01
        image = image.clamp(0, 1)
        label = label.unsqueeze(0)
        pred = model(image)
        loss = criterion(pred, label)
        loss.backward()
        optimizer.step()
    print(f'Epoch {epoch} train loss: {loss.item()}')
    model.eval()
    with torch.no_grad():
        val_loss = 0
        random.shuffle(val_dataset)
        for image, label, _ in val_dataset:
            image = image.unsqueeze(0)
            image = image + torch.randn_like(image) * 0.01
            image = image.clamp(0, 1)
            label = label.unsqueeze(0)
            pred = model(image)
            val_loss += criterion(pred, label).item()
        print(f'Epoch {epoch} val loss: {val_loss / len(val_dataset)}')
        pred = pred * 255
        pred = pred.clamp(0, 255)
        pred = pred.squeeze(0).permute(1, 2, 0).cpu().numpy() # (512, 512, 1)
        # save image
        pred = np.repeat(pred, 3, axis=2)
        Image.fromarray(pred.astype(np.uint8)).save(f'outputs/pred_{epoch}.png')
    if epoch % 10 == 0:
        torch.save(model, f'outputs/model_{epoch}.pt')
    




