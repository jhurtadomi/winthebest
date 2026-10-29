import { defineAstroPaperConfig } from "./src/types/config";

export default defineAstroPaperConfig({
  site: {
    url: "https://wintxx.xyz",
    title: "wintxx",
    description: "Offensive Security · Red Team · Pentesting",
    author: "wintxx",
    profile: "https://app.hackthebox.com/users/1942692",
    ogImage: "portait_wintxx.png",
    lang: "en",
    timezone: "America/Lima",
    dir: "ltr",
  },
  posts: {
    perPage: 5,
    perIndex: 5,
    scheduledPostMargin: 15 * 60 * 1000,
  },
  features: {
    lightAndDarkMode: true,
    dynamicOgImage: true,
    showArchives: true,
    showBackButton: true,
    editPost: {
      enabled: false,
    },
    search: "pagefind",
  },
  socials: [
    { name: "github",   url: "https://github.com/wintxx",                        linkTitle: "Wintxx on GitHub" },
    { name: "x",        url: "https://x.com/iamwintxx",                          linkTitle: "Wintxx on X / Twitter" },
    { name: "linkedin", url: "https://www.linkedin.com/in/wintxx/",              linkTitle: "Wintxx on LinkedIn" },
    { name: "discord",  url: "https://discord.com/users/1107531810344272004",    linkTitle: "Wintxx on Discord" },
  ],
  shareLinks: [
    { name: "x",        url: "https://x.com/intent/post?url=" },
    { name: "telegram", url: "https://t.me/share/url?url=" },
    { name: "whatsapp", url: "https://wa.me/?text=" },
    { name: "mail",     url: "mailto:?subject=See%20this%20post&body=" },
  ],
});
