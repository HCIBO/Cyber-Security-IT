from PIL import Image, ImageDraw, ImageFont
import argparse
import glob
import os

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--images", nargs="+", required=True)
parser.add_argument("-t", "--text", required=True)
parser.add_argument("--scale", type=float, default=1.5, help="Görsel büyütme oranı (örn: 1.5, 2)")
parser.add_argument("--font-percent", type=float, default=0.35, help="Yazı boyutu yüzdesi (0-1 arası, örn: 0.35 = %35)")
args = parser.parse_args()

image_paths = []
for pattern in args.images:
    image_paths.extend(glob.glob(pattern))

def get_huge_font(image_height):
    font_size = int(image_height * args.font_percent)

    try:
        return ImageFont.truetype("arial.ttf", font_size)
    except:
        try:
            return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", font_size)
        except:
            return ImageFont.load_default()

for image_path in image_paths:
    try:
        image = Image.open(image_path)

        exif_data = image.info.get("exif")

        if args.scale != 1:
            new_size = (
                int(image.width * args.scale),
                int(image.height * args.scale)
            )
            image = image.resize(new_size, Image.LANCZOS)

        image = image.convert("RGBA")
        overlay = Image.new("RGBA", image.size, (0, 0, 0, 0))
        draw = ImageDraw.Draw(overlay)

        width, height = image.size

        font = get_huge_font(height)

        bbox = draw.textbbox((0, 0), args.text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]

        x = (width - text_width) // 2
        y = height - text_height - int(height * 0.05)

        padding = int(height * 0.05)  

        box_coords = [
            x - padding,
            y - padding,
            x + text_width + padding,
            y + text_height + padding
        ]

        draw.rectangle(box_coords, fill=(0, 0, 0, 180))

        draw.text(
            (x, y),
            args.text,
            font=font,
            fill=(255, 255, 255, 255)
        )

        combined = Image.alpha_composite(image, overlay).convert("RGB")

        output_path = f"output_{os.path.basename(image_path)}"

        if exif_data:
            combined.save(output_path, exif=exif_data)
        else:
            combined.save(output_path)

        print(f"[+] Tamamlandı: {output_path}")

    except Exception as e:
        print(f"[!] Hata ({image_path}): {e}")
