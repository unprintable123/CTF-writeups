import torch
import torch.nn as nn
import numpy as np
flag='SUCTF{xxxxxxxxxxx?xxxxxxxxxxxxxxxxxxxxxxxxxxxxx}'
flag_list=[]
for i in flag:
    binary_str = format(ord(i), '09b')
    # print(binary_str)
    for bit in binary_str:
        flag_list.append(int(bit))
input=torch.tensor(flag_list, dtype=torch.float32)
print(input.shape)
n=len(flag)
class Net(nn.Module):

    def __init__(self):
        super(Net, self).__init__()
        self.linear = nn.Linear(n, n*n)
        self.conv=nn.Conv2d(1, 1, (2, 2), stride=1,padding=1)
        self.conv1=nn.Conv2d(1, 1, (3, 3), stride=3)

    def forward(self, x):
        x = x.view(1,1,3, 3*n)
        x = self.conv1(x)
        x = x.view(n)
        x = self.linear(x)
        x = x.view(1, 1, n, n)
        x=self.conv(x)
        return x
mynet=Net()
mynet.load_state_dict(torch.load('model.pth'))
mynet.eval()
real_output=mynet(input)

zero_tensor=torch.zeros(432)
zero_output=mynet(zero_tensor)

outputs = []
for i in range(432):
    zero_tensor=torch.zeros(432)
    zero_tensor[i]=1
    output=mynet(zero_tensor)
    outputs.append(output - zero_output)

real_output = real_output - zero_output
real_output = real_output.flatten()

outputs = torch.stack(outputs, dim=0).reshape(432, -1)

zero_tensor=torch.zeros(432)
zero_tensor[0]=1

# find v @ outputs == real_output
outputs = outputs.detach().numpy()
real_output = real_output.detach().numpy()
# compute rank of outputs
# dump outputs in json
with open('outputs.json', 'w') as f:
    import json
    o = outputs.tolist()
    json.dump(o, f)
with open('real_output.json', 'w') as f:
    import json
    o = real_output.tolist()
    json.dump(o, f)
with open('zero_output.json', 'w') as f:
    import json
    o = zero_output.detach().numpy().flatten().tolist()
    json.dump(o, f)




with open('fake.txt', 'w') as f:
    for tensor in output:
        for channel in tensor:
            for row in channel:
                f.write(' '.join(map(str, row.tolist())))
                f.write('\n')