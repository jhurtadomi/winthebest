---
title: "Mythic C2 MCP: Integrating AI with Command and Control Operations"
pubDatetime: 2026-08-06T05:47:30Z
draft: false
tags:
  - "Mythic C2"
  - "MCP"
  - "OpenCode"
  - "AI"
  - "Red Team"
description: "Integrating Model Context Protocol (MCP) with Mythic C2 and OpenCode to enhance offensive operations and command-and-control workflows with AI."
heroImage: "/assets/images/posts/MCPMythic/portada.png"
---
## Introduction

A few days ago I was working through an AI Offensive course where I covered several interesting topics. Some of them I had already explored on my own out of curiosity, but studying a subject more than once reinforces the concepts and improves retention. In this case, I will focus on the integration of a Mythic C2 MCP server with **OpenCode**, my current LLM of choice.

I previously used Claude — the course itself uses it — but I repeatedly ran into guardrails that block anything related to C2 infrastructure, implants, malware, and similar topics, which limits the learning experience considerably. OpenCode does not impose the same restrictions, making it the tool I rely on most for assistance with tooling syntax, language-specific questions, payload concepts, and similar offensive research tasks.

This post covers exactly that: integrating a Mythic C2 MCP server with OpenCode.

---

## Architecture

![Attack flow — Attacker → OpenCode → Mythic MCP Server → Mythic C2 Platform → Victim](/assets/images/posts/MCPMythic/arch.png)

The diagram above illustrates the full attack chain enabled by this integration. All components on the left side — the attacker's terminal, OpenCode, the Mythic MCP server, and the Mythic C2 platform — run on Linux. The victim endpoint runs on Windows.

The flow operates as follows:

1. **Attacker → OpenCode:** The operator issues natural language instructions directly from the terminal. There is no need to memorise API calls or navigate a web interface.
2. **OpenCode → Mythic MCP Server:** OpenCode routes the request to the Mythic MCP server via the Model Context Protocol. The MCP server exposes Mythic's functionality as a set of structured tools that the LLM can invoke.
3. **Mythic MCP Server → Mythic C2 Platform:** The MCP server translates the operator's intent into concrete API calls against Mythic's GraphQL/REST interface, querying session data, issuing tasks, or retrieving collected output.
4. **Mythic C2 Platform → Victim:** Mythic communicates with the implant running on the target machine over the configured C2 profile (HTTP, WebSocket, etc.), executing tasks and returning results back up the chain.

---

## Mythic C2

At a high level, Mythic is an open-source Command and Control (C2) framework for red team operations and the spiritual successor to Apfell/Apollo. Its main characteristics:

- **Architecture:** Docker-based (server, PostgreSQL, RabbitMQ, web UI)
- **Modular design:** separates C2 Profiles (channels: HTTP, DNS, WebSocket, SMB...) from Payload Types/Agents (Apollo, Poseidon, Medusa...)
- **Web interface:** real-time dashboard, per-implant interactive terminal, network graph
- **API:** REST + GraphQL for automation and external tool integration
- **Multi-operator:** collaborative operations with centralized logging
- **Task model:** asynchronous command execution, useful for realistic C2 traffic simulation

It is used in authorized adversary simulation exercises covering post-exploitation, persistence, and lateral movement — primarily to evaluate EDR/SIEM detection and response capabilities.

### Installation

> **Note:** Use a Linux host machine or WSL to make this tool work properly.

**Step 1: Verify system prerequisites**

```bash
sudo apt update && sudo apt upgrade -y
docker --version
docker-compose --version
```

**Step 2: Clone the official repository**

```bash
git clone https://github.com/its-a-feature/Mythic.git
cd Mythic
```

```bash
sudo make
```

![Mythic C2 directory structure](/assets/images/posts/MCPMythic/image1.png)

**Step 3: Start all Mythic services**

```bash
sudo ./mythic-cli start
```

**Step 4: Verify that all services are running correctly**

```bash
sudo ./mythic-cli status
```

**Step 5: Retrieve administrator credentials**

```bash
sudo ./mythic-cli config get admin_user
sudo ./mythic-cli config get admin_password
```

**Step 6: Install agents**

Install additional payload types directly from their GitHub repositories:

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/apfell
sudo ./mythic-cli install github https://github.com/MythicAgents/apollo
sudo ./mythic-cli install github https://github.com/MythicAgents/poseidon
```

**Step 7: Install C2 profiles**

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/websocket
```

![Mythic C2 agents installed](/assets/images/posts/MCPMythic/image2.png)
![Mythic C2 services running](/assets/images/posts/MCPMythic/image6.png)

---

## OpenCode

Installing OpenCode is straightforward — a single command from the documentation is all it takes:

```sh
curl -fsSL https://opencode.ai/install | bash
```

---

## MCP for Mythic C2

To integrate the Mythic MCP server with OpenCode, follow these steps:

### Step 1: Install `uv`

`uv` is the Python package manager used to run the MCP server in an isolated environment:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

![UV install](/assets/images/posts/MCPMythic/image3.png)

### Step 2: Clone the MCP server repository

The Mythic MCP server was developed by [@xpn](https://github.com/xpn) and is available on GitHub:

```sh
git clone https://github.com/xpn/mythic_mcp
```

### Step 3: Locate the `uv` binary path

Since OpenCode's config requires the absolute path to the `uv` binary, identify it first:

```sh
which uv
```

![uv binary path](/assets/images/posts/MCPMythic/image4.png)

### Step 4: Configure OpenCode

OpenCode is configured via a JSON file. Add the Mythic MCP server entry using the absolute paths from the previous step. The `command` array passes the Mythic credentials directly as arguments to `main.py`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "mythic_mcp": {
      "type": "local",
      "command": [
        "/home/iamwin/.local/bin/uv",
        "--directory",
        "/home/iamwin/Desktop/mythic_mcp",
        "run",
        "main.py",
        "mythic_admin",
        "<YOUR_MYTHIC_PASSWORD>",
        "localhost",
        "7443"
      ],
      "enabled": true
    }
  }
}
```

> Replace the `uv` path, the `--directory` path, and `<YOUR_MYTHIC_PASSWORD>` with your actual values.

![MCP Mythic in OpenCode](/assets/images/posts/MCPMythic/image5.png)

> This is a local lab environment, so the credentials shown above are not sensitive.

With all of the above in place, the Mythic MCP server is connected and ready. We can now use it from OpenCode to interact with our Mythic C2 instance in natural language.

---

## Functional Tests

Upon launching OpenCode, the MCP server is displayed as active, confirming that the integration was successful:

![OpenCode with Mythic MCP active](/assets/images/posts/MCPMythic/image7.png)

To validate the full workflow, we generate a Windows implant using the Apollo agent with an HTTP C2 profile, which will be delivered to the target machine.

![Mythic payload creation — OS selection](/assets/images/posts/MCPMythic/image8.png)
![Mythic payload creation — agent configuration](/assets/images/posts/MCPMythic/image9.png)
![Mythic payload creation — C2 profile setup](/assets/images/posts/MCPMythic/image10.png)

Once the implant is executed on the target, the callback registers in Mythic's **Active Callbacks** tab and we can begin interacting with the compromised host through the MCP.

![Mythic C2 — callback received](/assets/images/posts/MCPMythic/image11.png)

**Prompt 1** — Query active agents:

> What are the active agents in the Mythic C2? Use the Mythic MCP.

![Prompt 1 — active agents response](/assets/images/posts/MCPMythic/image12.png)

**Prompt 2** — Retrieve detailed session information:

> List all information about the active agent using the MCP.

![Prompt 2 — agent details response](/assets/images/posts/MCPMythic/image13.png)

**Prompt 3** — Task execution via natural language:

> Given that we have SYSTEM on ENGG, I have placed Mimikatz at `C:\RT\m\x64\m.exe` — dump everything and return the relevant results.

![Prompt 3 — credential dump via MCP](/assets/images/posts/MCPMythic/image14.png)

From this point, the operation can continue entirely through natural language prompts — the MCP handles the translation into Mythic API calls automatically.

---

Thanks for reading — I hope this is useful. If you have any questions, suggestions, corrections, or simply want to share something about this topic, my socials are on this blog — feel free to reach out.

Closing quote:

> "Simplicity is the ultimate sophistication."
>
> — Leonardo da Vinci
