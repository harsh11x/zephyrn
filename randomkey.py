import random
import string

def generate_unique_code():
    # Define the length of the code (between 7 and 10 characters)
    code_length = random.randint(7, 10)
    
    # Generate a random code using uppercase and lowercase alphabets
    code = ''.join(random.choices(string.ascii_letters, k=code_length))
    
    return code

# Generate and print the unique code
unique_code = generate_unique_code()
print("Generated unique code:", unique_code)
