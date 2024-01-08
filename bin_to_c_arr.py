import sys

# Check if the user provided the binary file as a command-line argument
if len(sys.argv) != 2:
    print("Usage: python binary_to_c_array.py <binary_file>")
    sys.exit(1)

# Get the binary file path from the command-line argument
input_binary_file = sys.argv[1]

# Read the binary file
with open(input_binary_file, "rb") as binary_file:
    binary_data = binary_file.read()

# Prepare the C array code with 10 bytes per line and a tab before the first byte (excluding the first and last lines)
c_array_code = "unsigned char binary[] = {\n"
for i, byte in enumerate(binary_data):
    if (i + 1) % 10 == 1:
        c_array_code += "\t"
    c_array_code += f"0x{byte:02X},"
    if (i + 1) % 10 == 0:
        c_array_code += "\n"
    elif (i + 1) == len(binary_data):
        c_array_code += "\n"
    else:
        c_array_code += " "

# Add a semicolon and close the array
c_array_code += "};"

# Print the C array code to the console
print(c_array_code)
