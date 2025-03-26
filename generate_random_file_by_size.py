import os
import random
from fpdf import FPDF
from faker import Faker
from PIL import Image
import numpy as np

def generate_pdf(target_size_mb, output_file):
    fake = Faker()
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    target_size_bytes = target_size_mb * 1024 * 1024
    paragraph_count = 0

    while True:
        paragraph = fake.paragraph(nb_sentences=10)
        pdf.multi_cell(0, 10, paragraph)
        pdf.ln()
        paragraph_count += 1

        pdf.output(output_file)
        current_size = os.path.getsize(output_file)
        print(f"PDF Paragraphs: {paragraph_count} - Size: {current_size / 1024:.2f} KB", end="\r")

        if current_size >= target_size_bytes:
            break

    print(f"\n PDF generated: {output_file} ({current_size / (1024 * 1024):.2f} MB)")

def generate_image(target_size_mb, output_file, image_format='PNG'):
    target_size_bytes = target_size_mb * 1024 * 1024
    width = height = 512

    while True:
        array = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
        img = Image.fromarray(array)

        img.save(output_file, format=image_format)
        current_size = os.path.getsize(output_file)
        print(f"Image Size: {width}x{height} - {current_size / 1024:.2f} KB", end="\r")

        if current_size >= target_size_bytes:
            break

        width = int(width * 1.1)
        height = int(height * 1.1)

    print(f"\n Image generated: {output_file} ({current_size / (1024 * 1024):.2f} MB)")

if __name__ == "__main__":
    print("1. Generate PDF file / Générer un fichier PDF")
    print("2. Generate Image file (PNG/JPG) / Générer une image (PNG/JPG)")

    choice = input("Your choice / Votre choix (1 or 2): ")

    try:
        size = float(input("Target file size (MB) / Taille du fichier (Mo) : "))
        filename = input("Output filename (e.g., file.pdf or img.jpg) / Nom du fichier de sortie : ") or "output.pdf"

        if choice == "1":
            generate_pdf(size, filename)
        elif choice == "2":
            ext = os.path.splitext(filename)[1].lower()
            format_map = {".png": "PNG", ".jpg": "JPEG", ".jpeg": "JPEG"}
            img_format = format_map.get(ext, "PNG")
            generate_image(size, filename, image_format=img_format)
        else:
            print(" Invalid choice / Choix invalide.")
    except ValueError:
        print(" Please enter a valid number / Veuillez entrer un nombre valide.")
