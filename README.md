# bli223dcryptex

:) 

```
 >  python ./bli223dcryptex.py st_tg582ndb_r10.2.5.2_bm.bin 

 >  binwalk  inflated_mst_tg582ndb_r10.2.5.2_bm.bin
```

```
 > python bliparser.py mst_tg582ndb_r10.2.5.2_bm.bin
```

```

********* fw fixed header decoding ********************************************************************* 

 [ptr :          ] filname           : mst_tg582ndb_r10.2.5.2_bm.bin
 [ptr : 000      ] imagetype         : BLI223WP0
 [ptr : 006      ] FIACODE           : WP
 [ptr : 020      ] branding          : 0
 [ptr : 028      ] flag??            : 00000000
 [ptr : 032      ] version           : 10.2.5.2
 [ptr : 040      ] hdrlength         : 0x00000163
 [ptr : 044      ] datalength        : 0x00741c5f
 [ptr : 048      ] crc32             : 520573bd
 [ptr :          ] computedhash      : e6854e3346e2114d2e61990fb9b6407bae6cd9a0
 [ptr :          ] decryptedhash     : e6854e3346e2114d2e61990fb9b6407bae6cd9a0
 [ptr :          ] integritycheck    : True
 [ptr :          ] aeskey            : 3032a8569805d4e48063808c70b8d0ec87a212d229bfe67f1d11c17d3b549b0f
 [prt : 0x741dc2 ] footer            :  
 [ptr : 356      ] imagetype         : MUTE
 [ptr : 310      ] board             : DANT-1 
 [ptr : 318      ] model1            : Technicolor TG582n 
 [ptr : 338      ] model2            : TG582n 
 [ptr : 346      ] ?????             : 200 
 [ptr : 351      ] flashaddr         : c0040000 

******************************************************************************************************** 


```



Happy hunting :) 

