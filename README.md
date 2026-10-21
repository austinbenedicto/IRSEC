# IRSEC
This is the repo we will use for IRSEC and maybe ccdc mini comp

Whenever you want to add something plz make a branch and have the naming convetion of it be
initails: what_you_are_doing

[HOW TO USE BRANCHES (click me)](git-workflow-guide.md)


                         ┌──────────────────────┐
                         │   GET LINUX MACHINE  │
                         └──────────┬───────────┘
                                    │
                                    ▼
                      ┌─────────────────────────┐
                      │    inventory_adv.sh     │
                      │                         │
                      │ • Inventory machine     │
                      │ • Users / admins        │
                      │ • Ports / services      │
                      │ • Create baseline       │
                      │ • Hash important files  │
                      └────────────┬────────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │ REVIEW INVENTORY  │
                         │                   │
                         │ Anything already  │
                         │ look suspicious?  │
                         └─────────┬─────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
                   YES                            NO
                    │                             │
                    ▼                             │
            Investigate manually                  │
            before trusting it                    │
                    │                             │
                    └──────────────┬──────────────┘
                                   │
                                   ▼
                      ┌─────────────────────────┐
                      │      persistence.sh     │
                      │                         │
                      │ Initial deep hunt for   │
                      │ persistence mechanisms  │
                      └────────────┬────────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │ START DEFENDING   │
                         └─────────┬─────────┘
                                   │
                                   ▼
                      ┌─────────────────────────┐
                      │        watch.sh         │◄──────────────┐
                      │                         │               │
                      │ LEAVE THIS RUNNING      │               │
                      │                         │               │
                      │ Watches for:            │               │
                      │ • New users             │               │
                      │ • New ports             │               │
                      │ • New services          │               │
                      └────────────┬────────────┘               │
                                   │                            │
                              ALERT?                            │
                         ┌─────────┴─────────┐                  │
                         │                   │                  │
                        YES                  NO                 │
                         │                   │                  │
                         ▼                   └──────────────────┘
                ┌─────────────────┐
                │ WHAT CHANGED?   │
                └────────┬────────┘
                         │
             ┌───────────┼───────────────────┐
             │           │                   │
          PORT /      SERVICE /           USER /
         CONNECTION    PROCESS          UNKNOWN
             │           │                   │
             ▼           ▼                   ▼
      ┌────────────┐  Investigate      ┌────────────────┐
      │ network.sh │  PID/service      │ persistence.sh │
      └──────┬─────┘                   └────────┬───────┘
             │                                  │
             │                                  │
             ▼                                  ▼
      WHO OWNS PORT?                   DEEP PERSISTENCE SCAN
      WHAT PROCESS?                    • SSH keys
      WHAT COMMAND?                    • Cron
      WHAT PARENT?                     • Systemd
      WHAT CONNECTION?                 • SUID/SGID
             │                         • Startup files
             │                         • ld.so.preload
             │                                  │
             └────────────────┬─────────────────┘
                              │
                              ▼
                     ┌──────────────────┐
                     │   SUSPICIOUS?    │
                     └────────┬─────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
                   YES                  NO
                    │                   │
                    ▼                   │
             ┌─────────────┐            │
             │ COLLECT     │            │
             │ EVIDENCE    │            │
             └──────┬──────┘            │
                    │                   │
                    ▼                   │
              INVESTIGATE               │
              & REMEDIATE               │
                    │                   │
                    └─────────┬─────────┘
                              │
                              ▼
                      CHECK SERVICES
                       STILL WORK
                              │
                              ▼
                   ┌─────────────────────┐
                   │ Run persistence.sh  │
                   │ again if necessary  │
                   └──────────┬──────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │ Return to       │
                     │ watch.sh        │
                     └────────┬────────┘
                              │
                              └────────────────────►
