MSG_HELP = """
**WireGuard Management:**
• `wgadd <client_name>` - Add new WireGuard client
• `wgremove <client_name>` - Remove WireGuard client
• `wgrename <old_name> <new_name>` - Rename WireGuard client
• `wglist` - List all WireGuard clients
• `wgconfig <client_name>` - Get client configuration

**Hashtag Management:**
• `tagremove <hashtag>` - Remove hashtag from navigation
• `taglist` - List all hashtags

**Statistics:**
• `wg` / `стата` - Show WireGuard statistics
• `wg ip` / `стата ip` - Show WireGuard statistics with client IP


**Zapret:**
• `zapretadd <file> <sites>` - Add sites to zapret list
• `zapretcheck <site>` - Check if site exists in zapret lists


**Help:**
• `help` / `помощь` - Show this help message

**Examples:**
• `wgadd myclient` - Create client named 'myclient'
• `wgrename myclient newclient` - Rename 'myclient' to 'newclient'
• `wgconfig myclient` - Get config for 'myclient'
• `wgremove myclient` - Delete 'myclient'
• `tagremove #python` - Remove #python hashtag
• `taglist` - Show all hashtags
• `zapretadd general example.com, test.org` - Add sites to general list
• `zapretcheck example.com` - Check presence in zapret files

All commands work with or without `!` prefix.
Russian aliases: `вгдобавить`, `вгудалить`, `вгпереименовать`, `вгсписок`, `вгконфиг`
"""

MSG_UNAUTHORIZED_ACCESS = (
    "🚫 **Access Denied!**\n\nYou are not authorized to use this bot."
)

CMD_WGADD = ("wgadd", "!wgadd", "вгдобавить")
CMD_WGREMOVE = ("wgremove", "!wgremove", "вгудалить")
CMD_WGLIST = ("wglist", "!wglist", "вгсписок", "вгклиенты", "wgclients")
CMD_WGCONFIG = ("wgconfig", "!wgconfig", "вгконфиг")
CMD_WGRENAME = ("wgrename", "!wgrename", "вгпереименовать")
CMD_HASHTAG_REMOVE = ("tagremove", "!tagremove", "тегудалить", "тегremove")
CMD_HASHTAG_LIST = ("taglist", "!taglist", "тегсписок", "тегlist")
CMD_HELP = ("help", "!help", "помощь", "команды", "commands", "wghelp", "!wghelp")
CMD_STATS = ("stats", "!stats", "статистика", "wgstats", "wg", "вг")
CMD_ZAPRET_ADD = ("zapretadd", "!zapretadd")
CMD_ZAPRET_CHECK = ("zapretcheck", "!zapretcheck")
