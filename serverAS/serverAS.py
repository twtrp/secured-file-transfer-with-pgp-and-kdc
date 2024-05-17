with open('MfromClient.txt', 'r') as input_file:
    content = input_file.read()

values = content.strip().split(',')
values = [value.strip() for value in values]

A = values[0]
B = values[1]

print(f"A: {A}")
print(f"B: {B}")

Respond_Path = 'C:/Users/HP/Documents/GitHub/hungsecurity/userA/MfromAS.txt'
with open(Respond_Path, 'w') as output_file:
    output_file.write(f"A: {A}\n")
    output_file.write(f"B: {B}\n")