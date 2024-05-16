with open('input_file.txt', 'rb') as input_file:
    content = input_file.read()

# Check if the content is "hi"
if content.strip() == "hi":
    # Write "hello" to another file
    with open('output_file.txt', 'wb') as output_file:
        output_file.write("hello")