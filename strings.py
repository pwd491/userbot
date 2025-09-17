MSG_HELP = """
**WireGuard Management:**
• `wgadd <client_name>` - Add new WireGuard client
• `wgremove <client_name>` - Remove WireGuard client
• `wglist` - List all WireGuard clients
• `wgconfig <client_name>` - Get client configuration

**Hashtag Management:**
• `tagremove <hashtag>` - Remove hashtag from navigation
• `taglist` - List all hashtags

**Statistics:**
• `wg` / `стата` - Show WireGuard statistics
• `wg ip` / `стата ip` - Show WireGuard statistics with client IP


**Help:**
• `help` / `помощь` - Show this help message

**Examples:**
• `wgadd myclient` - Create client named 'myclient'
• `wgconfig myclient` - Get config for 'myclient'
• `wgremove myclient` - Delete 'myclient'
• `tagremove #python` - Remove #python hashtag
• `taglist` - Show all hashtags

All commands work with or without `!` prefix.
Russian aliases: `вгдобавить`, `вгудалить`, `вгсписок`, `вгконфиг`
"""

MSG_UNAUTHORIZED_ACCESS = (
    "🚫 **Access Denied!**\n\nYou are not authorized to use this bot."
)

CMD_WGADD = ("wgadd", "!wgadd", "вгдобавить")
CMD_WGREMOVE = ("wgremove", "!wgremove", "вгудалить")
CMD_WGLIST = ("wglist", "!wglist", "вгсписок", "вгклиенты", "wgclients")
CMD_WGCONFIG = ("wgconfig", "!wgconfig", "вгконфиг")
CMD_HASHTAG_REMOVE = ("tagremove", "!tagremove", "тегудалить", "тегremove")
CMD_HASHTAG_LIST = ("taglist", "!taglist", "тегсписок", "тегlist")
CMD_HELP = ("help", "!help", "помощь", "команды", "commands", "wghelp", "!wghelp")
CMD_STATS = ("stats", "!stats", "статистика", "wgstats", "wg", "вг")
