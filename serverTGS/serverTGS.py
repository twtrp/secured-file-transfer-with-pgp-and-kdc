with open('MfromClient.txt', 'r') as input_file:
    content = input_file.read()

if content.strip() == "hi":
    with open('output_file.txt', 'w') as output_file:
        output_file.write("hello")