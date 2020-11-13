# Awesome-Android-Security ![awesome](https://awesome.re/badge.svg)
![Screenshot](img/androidsec.png)

 


# Table of Contents
- [Blog](#blog)
- [How To's](#how-tos)
- [Paper](#paper)
- [Books](#books)
- [Course](#course)
- [Tools](#tools)
  * [Static Analysis Tools](#Static-Analysis)
  * [Dynamic Analysis Tools](#Dynamic-Analysis)
  * [Online APK Analyzers](#Online-APK-Analyzers)
  * [Online APK Decompiler](#Online-APK-Decompiler)
  * [Forensic Analysis Tools](#Forensic-Analysis)
- [Labs](#labs)
- [Talks](#talks)
- [Misc](#misc)
- [Bug Bounty & Writeups](#Bug-Bounty-&-Writeup)
- [Cheat Sheet](#Cheat-Sheet)
- [Checklist](#Checklist)
- [Bug Bounty Report](#Bug-Bounty-Report)

# Blog
* [Evernote: Universal-XSS, theft of all cookies from all sites, and more](https://blog.oversecured.com/Evernote-Universal-XSS-theft-of-all-cookies-from-all-sites-and-more/)
* [Interception of Android implicit intents](https://blog.oversecured.com/Interception-of-Android-implicit-intents/)
* [AAPG - Android application penetration testing guide](https://nightowl131.github.io/AAPG/)
* [TikTok: three persistent arbitrary code executions and one theft of arbitrary files](https://blog.oversecured.com/Oversecured-detects-dangerous-vulnerabilities-in-the-TikTok-Android-app/)
* [Persistent arbitrary code execution in Android's Google Play Core Library: details, explanation and the PoC - CVE-2020-8913](https://blog.oversecured.com/Oversecured-automatically-discovers-persistent-code-execution-in-the-Google-Play-Core-Library/)
* [Android: Access to app protected components](https://blog.oversecured.com/Android-Access-to-app-protected-components/)
* [Android: arbitrary code execution via third-party package contexts](https://blog.oversecured.com/Android-arbitrary-code-execution-via-third-party-package-contexts/)
* [Android Pentesting Labs - Step by Step guide for beginners](https://medium.com/bugbountywriteup/android-pentesting-lab-4a6fe1a1d2e0)
* [An Android Hacking Primer](https://medium.com/swlh/an-android-hacking-primer-3390fef4e6a0)
* [An Android Security tips](https://developer.android.com/training/articles/security-tips)
* [OWASP Mobile Security Testing Guide](https://www.owasp.org/index.php/OWASP_Mobile_Security_Testing_Guide)
* [Security Testing for Android Cross Platform Application](https://3xpl01tc0d3r.blogspot.com/2019/09/security-testing-for-android-app-part1.html)
* [Dive deep into Android Application Security](https://blog.0daylabs.com/2019/09/18/deep-dive-into-Android-security/)
* [Pentesting Android Apps Using Frida](https://www.notsosecure.com/pentesting-android-apps-using-frida/)
* [Mobile Security Testing Guide](https://mobile-security.gitbook.io/mobile-security-testing-guide/)
* [Android Applications Reversing 101](https://www.evilsocket.net/2017/04/27/Android-Applications-Reversing-101/#.WQND0G3TTOM.reddit)
* [Android Security Guidelines](https://developer.box.com/en/guides/security/)
* [Android WebView Vulnerabilities](https://pentestlab.blog/2017/02/12/android-webview-vulnerabilities/)
* [OWASP Mobile Top 10](https://www.owasp.org/index.php/OWASP_Mobile_Top_10)
* [Practical Android Phone Forensics](https://resources.infosecinstitute.com/practical-android-phone-forensics/)
* [Mobile Pentesting With Frida](https://drive.google.com/file/d/1JccmMLi6YTnyRrp_rk6vzKrUX3oXK_Yw/view)
* [Zero to Hero - Mobile Application Testing - Android Platform](https://nileshsapariya.blogspot.com/2016/11/zero-to-hero-mobile-application-testing.html)
* [Detecting Dynamic Loading in Android Applications](https://sayfer.io/blog/dynamic-loading-in-android-applications-with-proc-maps/)

# How To's
* [How To Configuring Burp Suite With Android Nougat](https://blog.ropnop.com/configuring-burp-suite-with-android-nougat/)
* [How To Bypassing Xamarin Certificate Pinning](https://www.gosecure.net/blog/2020/04/06/bypassing-xamarin-certificate-pinning-on-android/)
* [How To Bypassing Android Anti-Emulation](https://www.juanurs.com/Bypassing-Android-Anti-Emulation-Part-I/)
* [How To Secure an Android Device](https://source.android.com/security)
* [Android Root Detection Bypass Using Objection and Frida Scripts](https://medium.com/@GowthamR1/android-root-detection-bypass-using-objection-and-frida-scripts-d681d30659a7)
* [Root Detection Bypass By Manual Code Manipulation.](https://medium.com/@sarang6489/root-detection-bypass-by-manual-code-manipulation-5478858f4ad1)
* [Magisk Systemless Root - Detection and Remediation](https://www.mobileiron.com/en/blog/magisk-android-rooting)
* [How to use FRIDA to bruteforce Secure Startup with FDE-encryption on a Samsung G935F running Android 8](https://github.com/Magpol/fridafde)

# Paper
* [AndrODet: An adaptive Android obfuscation detector](https://arxiv.org/pdf/1910.06192.pdf)
* [GEOST BOTNET - the discovery story of a new Android banking trojan](http://public.avast.com/research/VB2019-Garcia-etal.pdf)
* [Dual-Level Android Malware Detection](https://www.mdpi.com/2073-8994/12/7/1128)

   
# Books

 * [SEI CERT Android Secure Coding Standard](https://www.securecoding.cert.org/confluence/display/android/Android+Secure+Coding+Standard)
 * [Android Security Internals](https://www.oreilly.com/library/view/android-security-internals/9781457185496/)
 * [Android Cookbook](https://androidcookbook.com/)
 * [Android Hacker's Handbook](https://www.amazon.com/Android-Hackers-Handbook-Joshua-Drake/dp/111860864X)
 * [Android Security Cookbook](https://www.packtpub.com/in/application-development/android-security-cookbook)
 * [The Mobile Application Hacker's Handbook](https://www.amazon.in/Mobile-Application-Hackers-Handbook-ebook/dp/B00TSA6KLG)
 * [Android Malware and Analysis](https://www.oreilly.com/library/view/android-malware-and/9781482252200/)
 * [Android Security: Attacks and Defenses](https://www.crcpress.com/Android-Security-Attacks-and-Defenses/Misra-Dubey/p/book/9780367380182)
 * [Learning Penetration Testing For Android Devices](https://www.amazon.com/Learning-Penetration-Testing-Android-Devices-ebook/dp/B077L7SNG8)
* [Android Hacking 2020 Edition](https://www.amazon.com/Hacking-Android-TERRY-D-CLARK-ebook/dp/B08MD2D1SJ)

 
# Course

* [Android Reverse Engineering_pt-BR](https://www.youtube.com/watch?v=eHdDS2e_qf0&list=PL4zZ9lJ-RCbfv6f6Jc8cJ4ljKqENkTfi7) 
* [Learning-Android-Security](https://www.lynda.com/Android-tutorials/Learning-Android-Security/689762-2.html)
* [Advanced Android Development](https://developer.android.com/courses/advanced-training/overview)
* [Learn the art of mobile app development](https://www.edx.org/professional-certificate/harvardx-computer-science-and-mobile-apps)
* [Learning Android Malware Analysis](https://www.linkedin.com/learning/learning-android-malware-analysis)
* [Android App Reverse Engineering 101](https://maddiestone.github.io/AndroidAppRE/)
* [MASPT V2](https://www.elearnsecurity.com/course/mobile_application_security_and_penetration_testing/)
* [Android Pentration Testing(Persian)](https://www.youtube.com/watch?v=XqS_bA6XfNU&list=PLvVo-xqnJCI7rftDaiEtWFLXlkxN-1Nxn)
  
# Tools
     
#### Static Analysis

* [Apktool:A tool for reverse engineering Android apk files](https://ibotpeaches.github.io/Apktool/)
* [quark-engine - An Obfuscation-Neglect Android Malware Scoring System](https://github.com/quark-engine/quark-engine)

* [DeGuard:Statistical Deobfuscation for Android](http://apk-deguard.com/)
* [jadx - Dex to Java decompiler](https://github.com/skylot/jadx/releases)
* [Amandroid – A Static Analysis Framework](http://pag.arguslab.org/argus-saf)
* [Androwarn – Yet Another Static Code Analyzer](https://github.com/maaaaz/androwarn/)
* [Droid Hunter – Android application vulnerability analysis and Android pentest tool](https://github.com/hahwul/droid-hunter)
* [Error Prone – Static Analysis Tool](https://github.com/google/error-prone)
* [Findbugs – Find Bugs in Java Programs](http://findbugs.sourceforge.net/downloads.html)
* [Find Security Bugs – A SpotBugs plugin for security audits of Java web applications.](https://github.com/find-sec-bugs/find-sec-bugs/)
* [Flow Droid – Static Data Flow Tracker](https://github.com/secure-software-engineering/FlowDroid)
* [Smali/Baksmali – Assembler/Disassembler for the dex format](https://github.com/JesusFreke/smali)
* [Smali-CFGs – Smali Control Flow Graph’s](https://github.com/EugenioDelfa/Smali-CFGs)
* [SPARTA – Static Program Analysis for Reliable Trusted Apps](https://www.cs.washington.edu/sparta)
* [Gradle Static Analysis Plugin](https://github.com/novoda/gradle-static-analysis-plugin)
* [Checkstyle – A tool for checking Java source code](https://github.com/checkstyle/checkstyle)
* [PMD – An extensible multilanguage static code analyzer](https://github.com/pmd/pmd)
* [Soot – A Java Optimization Framework](https://github.com/Sable/soot)
* [Android Quality Starter](https://github.com/pwittchen/android-quality-starter)
* [QARK – Quick Android Review Kit](https://github.com/linkedin/qark)
* [Infer – A Static Analysis tool for Java, C, C++ and Objective-C](https://github.com/facebook/infer)
* [Android Check – Static Code analysis plugin for Android Project](https://github.com/noveogroup/android-check)
* [FindBugs-IDEA Static byte code analysis to look for bugs in Java code](https://plugins.jetbrains.com/plugin/3847-findbugs-idea)
* [APK Leaks – Scanning APK file for URIs, endpoints & secrets](https://github.com/dwisiswant0/apkleaks)
* [Trueseeing – fast, accurate and resillient vulnerabilities scanner for Android apps](https://github.com/monolithworks/trueseeing)
* [StaCoAn – crossplatform tool which aids developers, bugbounty hunters and ethical hackers](https://github.com/vincentcox/StaCoAn)
* [APKScanner](https://github.com/n3k00n3/APKScanner)
      
#### Dynamic Analysis

* [Mobile-Security-Framework MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
* [Magisk v20.2 - Root & Universal Systemless Interface](https://github.com/topjohnwu/Magisk5)
* [Runtime Mobile Security (RMS) - is a powerful web interface that helps you to manipulate Android and iOS Apps at Runtime](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security)
* [Droid-FF - Android File Fuzzing Framework](https://github.com/antojoseph/droid-ff)
* [Drozer](https://github.com/FSecureLABS/drozer)
* [Inspeckage](https://github.com/ac-pm/Inspeckage)
* [PATDroid - Collection of tools and data structures for analyzing Android applications](https://github.com/mingyuan-xia/PATDroid)
* [Radare2 - Unix-like reverse engineering framework and commandline tools](https://github.com/radareorg/radare2)
* [Cutter - Free and Open Source RE Platform powered by radare2](https://cutter.re/)
* [ByteCodeViewer - Android APK Reverse Engineering Suite (Decompiler, Editor, Debugger)](https://bytecodeviewer.com/)


        
#### Online APK Analyzers

* [Oversecured](https://oversecured.com/)
* [Android Observatory APK Scan](https:/androidobservatory.org/upload)
* [AndroTotal](http://andrototal.org/)
* [VirusTotal](https://www.virustotal.com/#/home/upload)
* [Scan Your APK](https://scanyourapk.com/)
* [AVC Undroid](https://undroid.av-comparatives.org/index.php)
* [OPSWAT](https://metadefender.opswat.com/#!/)
* [ImmuniWeb Mobile App Scanner](https://www.htbridge.com/mobile/)
* [Ostor Lab](https://www.ostorlab.co/scan/mobile/)
* [Quixxi](https://quixxisecurity.com/)
* [TraceDroid](http://tracedroid.few.vu.nl/submit.php)
* [Visual Threat](http://www.visualthreat.com/UIupload.action)
* [App Critique](https://appcritique.boozallen.com/)
* [Jotti's malware scan](https://virusscan.jotti.org/)
* [kaspersky scanner](https://opentip.kaspersky.com/)

#### Online APK Decompiler
* [Android APK Decompiler](http://www.decompileandroid.com/)
* [Java  Decompiler APk](http://www.javadecompilers.com/apk)
* [APK DECOMPILER APP](https://www.apkdecompilers.com/)
* [DeAPK is an open-source, online APK decompiler ](https://deapk.vaibhavpandey.com/)
* [apk and dex decompilation back to Java source code](http://www.decompiler.com/)
* [APK Decompiler Tools](https://apk.tools/tools/apk-decompiler/alternateURL/)

#### Forensic Analysis
* [Forensic Analysis for Mobile Apps (FAMA)](https://github.com/labcif/FAMA)
# Labs
  
* [OVAA (Oversecured Vulnerable Android App)](https://github.com/oversecured/ovaa)
* [DIVA (Damn insecure and vulnerable App)](https://github.com/payatu/diva-android)
* [OWASP Security Shepherd ](https://github.com/OWASP/SecurityShepherd)
* [Damn Vulnerable Hybrid Mobile App (DVHMA)](https://github.com/logicalhacking/DVHMA)
* [OWASP-mstg(UnCrackable Mobile Apps)](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes)
* [VulnerableAndroidAppOracle](https://github.com/dan7800/VulnerableAndroidAppOracle)
* [Android InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2)
* [Purposefully Insecure and Vulnerable Android Application (PIIVA)](https://github.com/htbridge/pivaa)
* [Sieve app(An android application which exploits through android components)](https://github.com/mwrlabs/drozer/releases/download/2.3.4/sieve.apk)
* [DodoVulnerableBank(Insecure Vulnerable Android Application that helps to learn hacing and securing apps)](https://github.com/CSPF-Founder/DodoVulnerableBank)
* [Digitalbank(Android Digital Bank Vulnerable Mobile App)](https://github.com/CyberScions/Digitalbank)
* [AppKnox Vulnerable Application](https://github.com/appknox/vulnerable-application)
* [Vulnerable Android Application](https://github.com/Lance0312/VulnApp)
* [Android Security Labs](https://github.com/SecurityCompass/AndroidLabs)
* [Android-security Sandbox](https://github.com/rafaeltoledo/android-security)
* [VulnDroid(CTF Style Vulnerable Android App)](https://github.com/shahenshah99/VulnDroid)
* [FridaLab](https://rossmarks.uk/blog/fridalab/)
* [Santoku Linux - Mobile Security VM](https://santoku-linux.com/)
* [AndroL4b - A Virtual Machine For Assessing Android applications, Reverse Engineering and Malware Analysis](https://github.com/sh4hin/Androl4b)

  
# Talks
  
* [One Step Ahead of Cheaters -- Instrumenting Android Emulators](https://www.youtube.com/watch?v=L3AniAxp_G4)
* [Vulnerable Out of the Box: An Evaluation of Android Carrier Devices](https://www.youtube.com/watch?v=R2brQvQeTvM)
* [Rock appround the clock: Tracking malware developers by Android](https://www.youtube.com/watch?v=wd5OU9NvxjU)
* [Chaosdata - Ghost in the Droid: Possessing Android Applications with ParaSpectre](https://www.youtube.com/watch?v=ohjTWylMGEA)
* [Remotely Compromising Android and iOS via a Bug in Broadcom's Wi-Fi Chipsets](https://www.youtube.com/watch?v=TDk2RId8LFo)
* [Honey, I Shrunk the Attack Surface – Adventures in Android Security Hardening](https://www.youtube.com/watch?v=EkL1sDMXRVk)
* [Hide Android Applications in Images](https://www.youtube.com/watch?v=hajOlvLhYJY)
* [Scary Code in the Heart of Android](https://www.youtube.com/watch?v=71YP65UANP0)
* [Fuzzing Android: A Recipe For Uncovering Vulnerabilities Inside System Components In Android](https://www.youtube.com/watch?v=q_HibdrbIxo)
* [Unpacking the Packed Unpacker: Reverse Engineering an Android Anti-Analysis Native Library](https://www.youtube.com/watch?v=s0Tqi7fuOSU)
* [Android FakeID Vulnerability Walkthrough](https://www.youtube.com/watch?v=5eJYCucZ-Tc)
* [Unleashing D* on Android Kernel Drivers](https://www.youtube.com/watch?v=1XavjjmfZAY)
* [The Smarts Behind Hacking Dumb Devices](https://www.youtube.com/watch?v=yU1BrY1ZB2o)
* [Overview of common Android app vulnerabilities](https://www.bugcrowd.com/resources/webinars/overview-of-common-android-app-vulnerabilities/)
* [Android security architecture](https://www.youtube.com/watch?v=3asW-nBU-JU)
* [Get the Ultimate Privilege of Android Phone](https://vimeo.com/335948808)
  
# Misc

* [Android Malware Adventures](https://docs.google.com/presentation/d/1pYB522E71hXrp4m3fL3E3fnAaOIboJKqpbyE5gSsOes/edit)    
* [Android-Reports-and-Resources](https://github.com/B3nac/Android-Reports-and-Resources/blob/master/README.md)
* [Hands On Mobile API Security](https://hackernoon.com/hands-on-mobile-api-security-get-rid-of-client-secrets-a79f111b6844)
* [Android Penetration Testing Courses](https://medium.com/mobile-penetration-testing/android-penetration-testing-courses-4effa36ac5ed)
* [Lesser-known Tools for Android Application PenTesting](https://captmeelo.com/pentest/2019/12/30/lesser-known-tools-for-android-pentest.html)
* [android-device-check - a set of scripts to check Android device security configuration](https://github.com/nelenkov/android-device-check)
* [apk-mitm - a CLI application that prepares Android APK files for HTTPS inspection](https://github.com/shroudedcode/apk-mitm)
* [Andriller - is software utility with a collection of forensic tools for smartphones](https://github.com/den4uk/andriller)
* [Dexofuzzy: Android malware similarity clustering method using opcode sequence-Paper](https://www.virusbulletin.com/virusbulletin/2019/11/dexofuzzy-android-malware-similarity-clustering-method-using-opcode-sequence/)
* [Chasing the Joker](https://docs.google.com/presentation/d/1sFGAERaNRuEORaH06MmZKeFRqpJo1ol1xFieUa1X_OA/edit#slide=id.p1)
* [Side Channel Attacks in 4G and 5G Cellular Networks-Slides](https://i.blackhat.com/eu-19/Thursday/eu-19-Hussain-Side-Channel-Attacks-In-4G-And-5G-Cellular-Networks.pdf)
* [Shodan.io-mobile-app for Android](https://github.com/PaulSec/Shodan.io-mobile-app)
* [Popular Android Malware 2018](https://github.com/sk3ptre/AndroidMalware_2018)
* [Popular Android Malware 2019](https://github.com/sk3ptre/AndroidMalware_2019)
* [Popular Android Malware 2020](https://github.com/sk3ptre/AndroidMalware_2020)    
    
   
# Bug Bounty & Writeup
* [Hacker101 CTF: Android Challenge Writeups](https://medium.com/bugbountywriteup/hacker101-ctf-android-challenge-writeups-f830a382c3ce)
* [Arbitrary code execution on Facebook for Android through download feature](https://medium.com/@dPhoeniixx/arbitrary-code-execution-on-facebook-for-android-through-download-feature-fb6826e33e0f)

* [RCE via Samsung Galaxy Store App](https://labs.f-secure.com/blog/samsung-s20-rce-via-samsung-galaxy-store-app/)

# Cheat Sheet 
* [Mobile Application Penetration Testing Cheat Sheet](https://github.com/sh4hin/MobileApp-Pentest-Cheatsheet)
* [ADB (Android Debug Bridge) Cheat Sheet](https://www.mobileqaengineer.com/blog/2020/2/4/adb-android-debug-bridge-cheat-sheet)
* [Frida Cheatsheet and Code Snippets for Android](https://erev0s.com/blog/frida-code-snippets-for-android/)

# Checklist
* [Android Pentesting Checklist](https://mobexler.com/checklist.htm#android)
* [OWASP Mobile Security Testing Guide](https://github.com/OWASP/owasp-mstg/tree/master/Checklists)

# Bug Bounty Report 
* [List of Android Hackerone disclosed reports](https://github.com/B3nac/Android-Reports-and-Resources)
* [How to report security issues](https://source.android.com/security/overview/updates-resources#report-issues)
