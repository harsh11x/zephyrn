from PIL import Image
import tkinter as tk
from tkinter import filedialog

# Function to load and display an image
def load_image():
    filepath = filedialog.askopenfilename()  # Open a file dialog to choose an image
    if filepath:
        img = Image.open(filepath)  # Open the image file
        img = img.resize((300, 300), Image.LANCZOS)  # Resize the image with LANCZOS resampling
        show_image(img)

# Function to show the image in a new window
def show_image(image):
    image.show()  # This opens the image using the default image viewer

# Create a simple Tkinter GUI to load the image
root = tk.Tk()
root.title("Image Resizer")

load_button = tk.Button(root, text="Load and Resize Image", command=load_image)
load_button.pack()

root.mainloop()

