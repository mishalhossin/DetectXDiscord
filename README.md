# DetectXDiscord

This is a Discord bot that can be used to scan files for viruses using the VirusTotal API. The bot listens for messages in a Discord server, and if a message contains a file attachment, it downloads the file, checks it for viruses using the VirusTotal API, and then reports the scan results back to the user.

## Getting Started

### Prerequisites

To use this bot, you will need the following:

- [Python 3.7 or higher]
- [A Discord bot token](https://discord.com/developers/applications)
- [A VirusTotal API key](https://support.virustotal.com/hc/en-us/articles/115002088769-Please-give-me-an-API-key)

### Installation

1. Clone this repository to your local machine.
2. Install the required packages using pip:

```bash
pip install discord requests hashlib aiohttp os
```
3. Set up `.env` file
{
  "DISCORD_TOKEN": "your_bots_discord_token",
  "VIRUSTOTAL_API_KEY": "your_virus_total_api_key"
}
## Run the bot
```bash
python main.py
```
