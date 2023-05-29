import discord
from discord.ext import commands
import requests
import hashlib
import aiohttp
import os

TOKEN = os.environ['DISCORD_TOKEN']
VIRUSTOTAL_API_KEY = os.environ['VIRUSTOTAL_API_KEY']

delete_message = False # Configure this

intents = discord.Intents.all()
bot = commands.Bot(command_prefix='!', intents=intents)
@bot.event
async def on_ready():
    print(f'{bot.user.name} has connected to Discord!')   

async def download_file(url, file_name):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            with open(file_name, 'wb') as file:
                while True:
                    chunk = await response.content.read(1024)
                    if not chunk:
                        break
                    file.write(chunk)       
                    
async def check_virus(file_path):
    with open(file_path, 'rb') as file:
        file_bytes = file.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()

    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
    response = requests.get(url, params=params)

    if response.status_code == 200:
        json_response = response.json()
        if json_response['response_code'] == 1:
            positives = json_response['positives']
            total = json_response['total']
            return positives > 0, f"{positives}/{total} antivirus software detected a threat in this file."
    return False, "Error occurred while scanning for viruses."


@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

    for attachment in message.attachments:
        if attachment.content_type.startswith('image/'):
            return
    
    if message.attachments:
        for attachment in message.attachments:
            file_name = attachment.filename
            file_url = attachment.url
            await download_file(file_url, file_name)
            is_infected, result = await check_virus(file_name)
            if is_infected:
                delete_message = True
                await message.channel.send(f"<@{message.author.id}> Virus scan detected. {result}")
            else:
                await message.channel.send(f"<@{message.author.id}> File is clean. {result}")
            os.remove(file_name)

    if delete_message:
        await message.delete()

    await bot.process_commands(message)

bot.run(TOKEN)
