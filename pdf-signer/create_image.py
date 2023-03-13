# https://wkhtmltopdf.org/
# https://github.com/jarrekk/imgkit
# import imgkit
# imgkit.from_file('test.html', 'out.png')


# pip3 install pillow

from PIL import Image, ImageDraw, ImageFont



def create_image_sign(text, file):

    # img = Image.new('RGBA', (400, 200),  (0, 0, 0, 1))
    # img = Image.new('RGBA', (400, 200),  (0, 0, 0, 1))
    # img = Image.new('RGBA', (400, 200),  '#00000000')
    img = Image.new('RGBA', (600, 120),  '#8f2828')
    img.save(f'{file}.png')

    img = Image.open(f'{file}.png')
    font = ImageFont.truetype("arial.ttf", size=20)
    idraw = ImageDraw.Draw(img)
    # idraw.text((25, 25), 'TEST test TeSt', font=font)
    idraw.text((150, 10), text, font=font, fill=(255, 255, 255, 200))
    img.save(f'{file}.png')

    return Image.open(f'{file}.png')



if __name__ == "__main__":
    # text = "text 35"
    # text = "g"*35 (400)
    text = f"""Документ подписан электронной подписью
Владелец: Иванов Иван Иванович
Сертификат: 6546544646464646464646464
Срок действия: с 01.01.2023 по 01.01.2024
"""



    file = "file"
    create_image_sign(text, file).show()


