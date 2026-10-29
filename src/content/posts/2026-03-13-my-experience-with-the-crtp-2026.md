---
title: "My Experience with the CRTP - 2026"
pubDatetime: 2026-03-13T11:00:00Z
draft: false
tags:
  - "CRTP"
  - "Active Directory"
  - "Red Team"
  - "Pentesting"
description: "My journey, preparation strategy, lab experiences, and tips for successfully passing the Altered Security Certified Red Team Professional (CRTP) exam."
heroImage: "/assets/images/posts/CRTP/portada_crtp.png"
---
## **ANECDOTE**

About a year ago, I was in my seventh semester of Systems Engineering, feeling like I was at a dead end. With graduation getting closer every day, I didn't even have a defined resume. While it's true I had completed many software and management projects, honestly, they didn't fulfill me. I'd had a first encounter with Information Security and Linux in a faculty course and got hooked, but at that time, I saw it more as a distant dream than a real career path.

Everything changed one night during an Instagram conversation with a friend. She was trying to sell me some products (lol), but we ended up talking about the future. She asked me what I planned to do for a living, and I finally let out what I had been holding back: "I'm not sure, but Ethical Hacking really catches my attention, and I don't know what to do." At that moment, I was about to take the first steps toward my thesis and research focused on Software; I felt I was going against what I truly wanted. It's not that I don't like development—it's actually very cool—but we all have something that hooks us more.

She mentioned she had a friend, a graduate, who worked in that field. She told him about me, put us in touch, and we started talking. He gave me advice, the motivation I needed, and became the bridge to what would come next.

This friend got me a meeting with the Director of my School. I knew he was a reference in the field, so I went the next day with the typical nerves of someone seeking an opportunity, but with clear ideas for the first time. I told him about my desire to learn and what I was passionate about.

I didn't expect his response. It wasn't just advice: it was a direct invitation to join his research group in Networks and Security.

From that moment on, something clicked. In every project, I've had the freedom to dive deep into what truly interests me: Cybersecurity, Red Teaming, and Pentesting. I went from not knowing what to do with my career to learning in the trenches alongside people who have been doing this for years. It was exactly that push that drove me to take the next steps, following a path of certifications like CRTA, eJPT, and CRTeamer, leading up to the CRTP, which I consider my greatest achievement so far.

Looking back, none of this would have been the same without the right people at the right time. Therefore, I want to deeply thank Saskia, Howard, and Dr. William, Director of the School of Engineering, and my university classmate Jorge, who are responsible for me being dedicated to what I am truly passionate about today.

Also, to the friends I made on networks like LinkedIn who contributed so much to the knowledge I have now. Thank you Francisco Flores, Manuel Veas, and my bro Jacob.

> *Now, let's start talking about the Certification!*

## **INTRODUCTION**

The Certified Red Team Professional (CRTP) is a beginner-to-intermediate level certification provided by Altered Security. It includes a course with over 12 hours of video content plus a lab environment that we will discuss in detail later. The certification focuses exclusively on exploiting Active Directory environments, following a very clear methodology that ranges from Reconnaissance to Persistence and Data Exfiltration.

What makes it especially interesting is that the entire compromise of the AD environment is done from Windows. CMD and PowerShell will be your best friends here, and yes—for many, including myself—this was a significant shift, as we were used to interacting with AD from Linux. The course material provides everything you need: Windows binaries, PowerShell scripts, and the native AD module that comes with the operating system itself.

Below is an image of the methodology taught in the course.

![CRTP course methodology](/assets/images/posts/CRTP/metodologia.png)


## **THE COURSE**

Before getting into the details, I want to be honest: I hadn't been working seriously with Active Directory environments for very long. But when I saw the discount Altered Security launched — a 20% off that brought the one-month course down to just $199 USD — I simply couldn't resist. I felt it was the perfect moment to take the leap.

Something I want to mention about how I studied: I started by watching the instructor's videos, but I found myself getting quite distracted. What really worked for me was reading. When you purchase the course, you get the full slides the instructor uses, along with lab manuals in two formats — using Sliver and a more manual approach — and that's what truly helped me understand the material. If you are someone who learns better by reading, you will feel very comfortable here.

### **What do you get for your investment?**

The material is designed to guide you step-by-step, without underestimating you. Upon enrollment, you get access to:

- **Over 12 hours of video content:** Taught by Nikhil Mittal. No filler; every section is focused on techniques that you will apply in both the lab and the exam.
- **Instructor Slides:** A resource I didn't expect to be so useful, which ended up becoming my primary study material.
- **Lab Manuals (PDF):** Featuring two approaches for every attack:
    1. **Without C2:** Manual, using local tools, binaries, and scripts. This is fundamental to understanding how the protocols work under the hood.
    2. **With C2 (Sliver):** A modern and powerful framework that elevates the experience to a real-world Red Teaming level.
- **The Tools:** Binaries, PowerShell scripts, and modules ready to use directly from Windows.


### **The Learning Curve**

Something to keep in mind before purchasing: Altered Security considers the 1-month lab plan to be for someone with solid experience in Red Teaming and Enterprise Security. I chose that plan, which turned this into a real challenge — I couldn't afford to waste a single day.

![Study session notes](/assets/images/posts/CRTP/estudio.png)

This forced me to change my approach from the start. I set the videos aside because they were too distracting for me, and instead, I focused on carefully reading the instructor's slides, researching what I didn't understand, and ensuring I grasped every concept before moving on to the next. It wasn't about moving fast; it was about moving effectively.

What I struggled with the most was adapting to the tools and their syntax. Every tool has its own logic, and you have to be very meticulous — one wrong parameter and the attack simply won't work. However, that precision the course demands is exactly what prepares you for working in real-world environments.

## **THE LAB**

After reading through the slides and feeling like I had the necessary foundation, my mind was set on one thing: "It's lab time."

I started on December 25th. On Christmas. After Christmas Eve and spending time with my family, I headed to my room to fire up the VPN and start the Learning Objectives — because that's just how those of us who are passionate about this operate.

I was on vacation, so my time was almost exclusively dedicated to the lab. But then a hectic week hit: I had to help out at home, handle university enrollment paperwork, and unintentionally, I stayed away from the lab for almost a week and a half. It hurt because I only had one month of access, and every day counted.

When I returned, I went at it with everything I had. I finished it, and still had enough time to go through half of it a second time.

Since it's a guided lab, you're never completely in the dark. If you had doubts, you could check the manual, do your own research, or consult the Attack Roadmap provided by the course. That support system makes the lab challenging, but never frustrating.

![Lab environment view](/assets/images/posts/CRTP/lab.png)

![Lab notes](/assets/images/posts/CRTP/apuntes_lab.png)

## **THE EXAM**

Once I completed the course and the lab, I picked the date: Saturday, February 28, 2026.

Something important before you start: the exam instance does not provide the tools. You must have them prepared in advance to transfer them to the jump box you'll be operating from — this is not the time to improvise.

I started at approximately 9:10 AM with two Monsters on my desk and finished around 2:00 AM. Yes, a bit late, but I intentionally went slow. As I progressed, I made sure to note down every successful command along with its output and took screenshots of everything, knowing I would need that material for the report.

Without spoilers, the exam consists of 5 machines, not counting the one provided for operations. All of them have misconfigurations, and each one targets something different, so enumeration is key. There are no tasks that require brute force — attacks like Kerberoasting and AS-REP Roasting are out of the scope of the exam.


### **The Report**

Compromising the environment is not enough to pass. You must also write a professional, WriteUp-style report describing step-by-step how you reached each machine. You are given 48 additional hours after the 24-hour exam period for this — plenty of time if you took diligent notes during the process.

After finishing the exam, I slept for about 6 hours and then got up to start writing. I used Word, took the images from this repository to design the cover, and built the report using everything I had collected.

> 📄 Report template: [Altered-Security-Reporting](https://github.com/didntchooseaname/Altered-Security-Reporting)

![Report cover](/assets/images/posts/CRTP/report.png)

![Report content](/assets/images/posts/CRTP/report1.png)

After about five days, I received an email saying that I had passed the exam:

![Approval email](/assets/images/posts/CRTP/email.png)


## **CONCLUSIONS**

The CRTP is not just another certification on a resume. For me, it was a validation: a confirmation that the path I've chosen is the right one, and that with discipline and consistency, you can go much further than you ever imagined.

I'm taking away much more than just technical knowledge. I learned how to navigate an Active Directory environment using a real-world methodology, how to adopt an attacker's mindset within Windows, and how to document every step with the professional rigor that the industry demands. But above all, I've gained confidence — the kind that only comes from facing a difficult challenge and overcoming it.

If you're thinking about taking the CRTP, I recommend it without hesitation, whether you're just starting in the Red Team world or already have some experience. The course guides you without underestimating you, the lab truly puts you to the test, and the exam forces you to prove that you understand the process, not just that you've memorized commands.

As for me, it doesn't end here. The CRTP has sharpened my appetite for Active Directory, and I want to keep digging deeper. There is so much more to explore, and I fully intend to do so.

![CRTP Certificate](/assets/images/posts/CRTP/crtp_cert.jpg)


## **TIPS**

Before wrapping up, I want to share some tips based on my own experience. I'm sure they will save you time and more than one headache:

- **Have your tools ready and well-selected.** As I mentioned before, the exam machine doesn't come with anything pre-installed. Prepare only the necessary tools — don't try to transfer everything, as the overhead can lead to slowness, and that's the last thing you want during the exam.

- **Don't forget AMSI Bypass, PowerShell Bypass, and InviShell.** These are the first things you should have ready before you start working.

- **As soon as you compromise a machine with high privileges, disable all security.** Working with your tools without restrictions will make your life much easier.

- **Dump everything you can.** Mimikatz and SafetyKatz are your best allies at that moment.

- **Enumerate well and be thorough with the outputs.** Already have a domain user? Launch BloodHound immediately; it will give you a clear view of the ACLs and potential attack paths.

- **Relax.** If you can't exploit a misconfiguration on the first try, don't panic. Analyze it calmly or check some blogs — the answer is almost always out there.

- **Enumeration is key.** A friend who had already passed the cert told me exactly that when I asked for the most important piece of advice. He was right: with good enumeration, the path appears right before your eyes.

- **Create your own CheatSheet.** Having all the techniques in one place prevents you from wasting time searching in the middle of the exam.

- **Take notes and screenshots from the very beginning.** Your report will thank you later.

- **Research on your own beyond the course.** In the exam, I encountered things that aren't explicitly taught in the material, but the foundations provided by the course are enough to reason through and solve them. Don't rely solely on what's in the slides.


## **SUPPORT RESOURCES**

- [harmj0y Blog](https://blog.harmj0y.net/blog/)
- [Active Directory Pro](https://activedirectorypro.com/blog/)
- [AD Security](https://adsecurity.org/)
- [SpecterOps Blog](https://specterops.io/blog/tag/active-directory/)
- [Red Team Notes](https://www.ired.team/)

---

> If you've made it this far, thanks for reading. I hope this experience proves helpful to you, whether it encourages you to take the plunge or simply gives you an idea of what to expect. See you in the next post.
