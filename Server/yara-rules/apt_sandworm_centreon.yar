YARAЦ          ж         ╢      └	  v      А
  Ў                 "%      6  X)      ╓  .,        28        :H      А  ║O                                                                                           Ь             └      P                           H             А     И                           Ї             @     а                           У                   ╪                           b             └                                2             А     H                           ╓             @     А                           ┤                   ╕                           l             └     Ё                           j	             А     ░                           n
             @     ╚                           x              	     и             ····················································         %                     M      Y                     ж      ░                     э      Є                     ¤           F                                               %                     M      ┴                    ж      ░                     э      Є                     ¤           P                                               p                    M      }                    ж      ░                     э      Є                     ¤           Z                      н                         p                    M                          ж      ░                     э      Є                     ¤           Z                      G                         p                    M      ┐                    ж      ░                     э      Є                     ¤           P                      ,                         p                    M      Щ                    ж      ░                     э      Є                     ¤           P                                                p                    M      i                    ж      ░                     э      Є                     ¤           P                      ▒                         p                    M                          ж      ░                     э      Є                     ¤           P                      Г                         p                    M      ┌                    ж      ░                     э      Є                     ¤           P                      7                         p                    M      С                    ж      ░                     э      Є                     ¤           P                      ▄                         p                    M      Л	                    ж      ░                     э      Є                     ¤           P                      ё	                         p                    M      Х
                    ж      ░                     э      Є                     ¤           P                      ╔
                         Ъ                    M      ╪                    ж      ░                     э      Є                     ¤           P                      ╔
                	       ┌║·┌║·           0                     +  	      ┌║·┌║·           B                     6  	      ┌║·┌║·           U                     P  	      ┌║·┌║·     	      u                     j  	      ┌║·┌║·           З                       	      ┌║·┌║·           Ц                     П  	      ┌║·┌║·          +                     '  	                F      ▄                     ╥  	      ┌║·┌║·          .                     #  	  	    ┌║·┌║·    @      R                     G  	  
    ┌║·┌║·    +      Щ                     У  	      ┌║·┌║·    (      ╦                     ┼  	      ┌║·┌║·    $      n                     l  	      ┌║·┌║·          Q                     l  	      ┌║·┌║·          $                     l  )     ┌║·┌║·                                   l  K     ┌║·┌║·          и                     l  	      ┌║·┌║·          \                     l  	      ┌║·┌║· 	   
      	                     l  	      ┌║·┌║· 	         	                     l  	      ┌║·┌║· 	         	                     l  	      ┌║·┌║· 	         '	                     l  	      ┌║·┌║· 	   
      6	                     l  	      ┌║·┌║· 	         A	                     l  	      ┌║·┌║· 	         M	                     l  	      ┌║·┌║· 	         Z	                     l  K      ┌║·┌║· 
                                  
  K      ┌║·┌║· 
                                  (
  K      ┌║·┌║· 
                                  :
  K      ┌║·┌║· 
                                  L
  K     ┌║·┌║· 
                                  ^
  	      ┌║·┌║·          ї
                     ю
  	       ┌║·┌║·                                 	  !    ┌║·┌║·    2      5                     .  	  "    ┌║·┌║·          o                     h  	  #    ┌║·┌║·                                 	  $    ┌║·┌║·          %                       	  %    ┌║·┌║·          ;                     -  	  &    ┌║·┌║·    
      Q                     C  	  '    ┌║·┌║·          e                     \  	  (    ┌║·┌║·          А                     w  	  )    ┌║·┌║·    
      Ы                     Т  	  *    ┌║·┌║·          м                     ж  	  +    ┌║·┌║·    
      ╛                     ╕  	  ,    ┌║·┌║·    	      ╧                     ╔  	  -    ┌║·┌║·          ▀                     ┘  	  .    ┌║·┌║·          є                     э  	  /    ┌║·┌║·    	      
                           ····················default WEBSHELL_PAS_webshell author FR/ANSSI/SDO (modified by Florian Roth) description Detects P.A.S. PHP webshell - Based on DHS/FBI JAR-16-2029 (Grizzly  Steppe) reference https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf date 2021-02-15 score id 862aab77-936e-524c-8669-4f48730f4ed5 $php <?php $strreplace (str_replace( $md5 .substr(md5(strrev($ $gzinflate gzinflate $cookie _COOKIE $isset isset WEBSHELL_PAS_webshell_ZIPArchiveFile Detects an archive file created by P.A.S. for download operation 081cc65b-e51c-59fc-a518-cd986e8ee2f7 $s1 Archive created by P.A.S. v. WEBSHELL_PAS_webshell_PerlNetworkScript FR/ANSSI/SDO Detects PERL scripts created by P.A.S. webshell 1625b63f-ead7-5712-92b4-0ce6ecc49fd4 $pl_start #!/usr/bin/perl
$SIG{'CHLD'}='IGNORE'; use IO::Socket; use FileHandle; $pl_status $o=" [OK]";$e=" Error: " $pl_socket socket(SOCKET, PF_INET, SOCK_STREAM,$tcp) or die print "$l$e$!$l $msg1 print "$l OK! I\'m successful connected.$l" $msg2 print "$l OK! I\'m accept connection.$l" WEBSHELL_PAS_webshell_SQLDumpFile Detects SQL dump file created by P.A.S. webshell 4c26feeb-3031-5c91-9eeb-4b5fe9702e39 $ -- [ SQL Dump created by P.A.S. ] -- APT_MAL_Sandworm_Exaramel_Configuration_Key Detects the encryption key for the configuration file used by Exaramel malware as seen in sample e1ff72[...] 8078de62-3dd2-5ee0-8bda-f508e4013144 odhyrfjcnfkdtslt APT_MAL_Sandworm_Exaramel_Configuration_Name_Encrypted Detects the specific name of the configuration file in Exaramel malware as seen in sample e1ff72[...] 1c06f5fc-3435-51cd-92fb-17a4ab6b63ad configtx.json APT_MAL_Sandworm_Exaramel_Configuration_File_Plaintext Detects contents of the configuration file used by Exaramel (plaintext) 6f0d834b-e6c8-59e6-bf9a-b4fd9c0b2297 APT_MAL_Sandworm_Exaramel_Configuration_File_Ciphertext Detects contents of the configuration file used by Exaramel (encrypted with key odhyrfjcnfkdtslt, sample e1ff72[...] 763dbb17-2bad-5b40-8a7b-b71bc5849cd9 o╢щгН^▌╛╘ APT_MAL_Sandworm_Exaramel_Socket_Path Detects path of the unix socket created to prevent concurrent executions in Exaramel malware 3aab84c9-9748-5d11-9cd7-efa9151036cf /tmp/.applocktx APT_MAL_Sandworm_Exaramel_Task_Names Detects names of the tasks received from the CC server in Exaramel malware 185f2f3b-bf5c-54af-bca2-400d08bf9c91 App.Delete App.SetServer App.SetProxy App.SetTimeout App.Update IO.ReadFile IO.WriteFile OS.ShellExecute APT_MAL_Sandworm_Exaramel_Struct Detects the beginning of type _type struct for some of the most important structs in Exaramel malware 8282e485-966c-554d-8e41-70dc1657f5ea $struct_le_config $struct_le_worker $struct_le_client $struct_le_report $struct_le_task APT_MAL_Sandworm_Exaramel_Strings_Typo Detects misc strings in Exaramel malware with typos fdc79b87-eb9e-5751-9474-ff653b073165 $typo1 /sbin/init | awk  $typo2 Syslog service for monitoring 
 $typo3 Error.Can't update app! Not enough update archive. $typo4 :"metod" APT_MAL_Sandworm_Exaramel_Strings FR/ANSSI/SDO (composed from 4 saparate rules by Florian Roth) Detects Strings used by Exaramel malware $persistence1 systemd $persistence2 upstart $persistence3 systemV $persistence4 freebsd rc $report1 systemdupdate.rep $report2 upstartupdate.rep $report3 remove.rep $url1 /tasks.get/ $url2 /time.get/ $url3 /time.set $url4 /tasks.report $url5 /attachment.get/ $url6 /auth/app k       %@ Pg/   %A   f/G   BB          8      p      и      р                                 P         y      %@pf/>   ?    И  /,   BB   И     └     °          1$   ?B   0     h                 '      ?B   а                 &      BB   ╪                 &      BB                    &      BB   H                 &      BB   А                 &      BB   ╕                 e   	   BB   Ё     (     `     Ш     ╨          @     x          	       K   
   ?B   ░     ш           X     Р          
       B      ?B   ╚           8     p                 ^     ?B   0	     h	     а	     ╪	     
     H
          /5   BB   и     р          P          1a   BB   и     р          P          /,   BB   И     └     °          1t   ?B   0	     h	     а	     ╪	     
     H
          /,   BB   И     └     °                  в{в"вHвoвsвtвsв"в:в[в"┤
  в"в]в,в"вPвrвoвxвyв"в:в"┤   в"в,в"вVвeвrвsвiвoвnв"в:в"┤   в"в,в"вGвuвiвdв"в:в"нв"в:в"вdвiвuвGв"в,в"┤   в"в:в"вnвoвiвsвrвeвVв"в,в"┤   в"в:в"вyвxвoвrвPв"в,в]в"┤
  в"в[в:в"вsвtвsвoвHв"в{нвpв в в в в в в вXв в в в в в в вGв-в(вBд Ё╡  внв╡  д ЁвBв(в-вGв в в в в в в вXв в в в в в в вpнв0в в в в в в в в0в в в в в в в вFвjввтд Ё╡  внв╡  д ЁвтввjвFв в в в в в в в0в в в в в в в в0нв в в в в в в в вв в в в в в в в{вjвIвДд Ё╡  внв╡  д ЁвДвIвjв{в в в в в в в вв в в в в в в в нв0в в в в в в в в(в в в в в в в в┐в5вв∙д Ё╡  внв╡  д Ёв∙вв5в┐в в в в в в в в(в в в в в в в в0нвPв в в в в в в в в в в в в в в вИв`вбв┼д Ё╡  внв╡  д Ёв┼вбв`вИв в в в в в в в в в в в в в в вPн                                                                                    	d                                                      "  $,      #>         )<                     /\  0              #Ц  .X  V #Ь  "о          ;   "  =4  /Ж     6P  /░  B&   \      Z     G   H   "  J                         Q$      %М  T  )\          \  /^ @а  PT  Dд  0h ^(   "  `0  N╚  b   "       "  f  cB  h2  a@  j.  bN         n     p8  q  qD  o6  t"  JX v  u:  kV  tF  z
  kb  |  tx  ur  qZ  zJ  ef  T~  f▐  VИ  /t ;x 0О Eb Й  <М tТ  nЪ  n┌  uШ  sм  uB -И t╛  wt  {Ю  t╞  t╩  T` u╪  tH BТ bN iv vJ /к cR fp     PЪ jL  F      .     i|                     <   \   ~      eЬ m~    qЖ     ╖     jШ  \         tФ         └  qв вT        yЦ        eо  &   "       .              /м    f▓ f╢ uЮ  \   \             u░                "   .      #Є /▐             /ц     %Ў     %°            \      C╨      \       
         /■     /            Dш  \         S╪  \  6         X╘                                     m╕     j└ n╝     f┌ f▄ \ф     u║ t╛ ъl P                         fь             eю                             f  Е╩             zъ                 i o
     v·                 s                                                                                             др                                                                                     ╞┬                                                                                                                             у╠                                                                                 ·╚                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 )   /   '   %   &       #   !   0   -   .                                                                   *   "                       
   	                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       8                                     p                                     и                                     р                                                                         P                                    И                                    └                                    °                          %          0                          +          h                  
   Р  (          а                  
   Ё             ╪                                                              	          H           ╦                     А                                    ╕                                    Ё                                    (                                    `                  
   °            Ш                  
                ╨                                                                        @                                    x                                    ░     °                          ш     ^     Г                          ─     щ                    X     *     O                    Р     Р     ╡                    ╚                                                                         8                                    p                                    и                                    р                                                      
   x            P                                    И                                    └                  
               °                                    0	                                    h	                                    а	                  
   ╕            ╪	                  
   Р            
                                    H
                                    0                             (             0                          (      @      H      `      h      А      И      а      и      0                
       
      
      
         h      P      X   
   (   
   0   
   8   
   @      а      И      Р   
   P   
   X   
   `   
   h      ╪      └      ╚   
   x   
   А   
   И   
   Р           °         
   а   
   и   
   ░   
   ╕      H     0     8  
   ╚   
   ╨   
   ╪   
   р      #      ,      5      >      G      P      H      P      `      X      h      └      ╚      р      ш                       (     @     H     `     h     А     h     p  
   Ё   
   °   
      
        u      А      И      Ш      Р      а      А     И     а     и     └     ╚     р     ш                      (     ╕     а     и  
     
      
   (  
   0     Ё     ╪     р  
   @  
   H  
   P  
   X     (            
   h  
   p  
   x  
   А     `     H     P  
   Р  
   Ш  
   а  
   и     Ш     А     И  
   ╕  
   └  
   ╚  
   ╨     Э      о      ╖      └      ▄      х      ╕      └      ╨      ╚      ╪      @     H     `     h     А     И     а     и     └     ╚     р     ш     ╨     ╕     └  
   р  
   ш  
   Ё  
   °          Ё      °                                       (     @     H     `     h     А     И     а     и          Ё     °  
     
     
     
         3     (     0     @     8     H     └     ╚     р     ш                      (     @     H     `     h     @     (     0  
   0  
   8  
   @  
   H     Y     `     h     x     p     А     А     И     а     и     └     ╚     р     ш                      (     x     `     h  
   X  
   `  
   h  
   p          Ш     а     ░     и     ╕     @     H     `     h     А     И     а     и     └     ╚     р     ш     ░     Ш     а  
   А  
   И  
   Р  
   Ш     е     ╨     ╪     ш     р     Ё                      (     @     H     `     h     А     И     а     и     ш     ╨     ╪  
   и  
   ░  
   ╕  
   └     ╦                          (     └     ╚     р     ш                      (     @     H     `     h                  
   ╨  
   ╪  
   р  
   ш     X     @     H  
   °  
      
     
        Р     x     А  
      
   (  
   0  
   8     ╚     ░     ╕  
   H  
   P  
   X  
   `           ш     Ё  
   p  
   x  
   А  
   И     8           (  
   Ш  
   а  
   и  
   ░     p     X     `  
   └  
   ╚  
   ╨  
   ╪     и     Р     Ш  
   ш  
   Ё  
   °  
         ё     ·                         '     0     @     H     X     P     `     А     И     а     и     └     ╚     р     ш                      (     р     ╚     ╨  
     
     
      
   (                  
   8  
   @  
   H  
   P     P     8     @  
   `  
   h  
   p  
   x     И     p     x  
   И  
   Р  
   Ш  
   а     └     и     ░  
   ░  
   ╕  
   └  
   ╚     W     `     i     r     {     x     А     Р     И     Ш     @     H     `     h     А     И     а     и     └     ╚     р     ш     °     р     ш  
   ╪  
   р  
   ш  
   Ё     0             
      
     
     
        h     P     X  
   (  
   0  
   8  
   @     а     И     Р  
   P  
   X  
   `  
   h     в     л     ┤     ╜     ░     ╕     ╚     └     ╨      	     	      	     (	     @	     H	     `	     h	     А	     И	     а	     и	     ╪     └     ╚  
   x  
   А  
   И  
   Р          °        
   а  
   и  
   ░  
   ╕     H     0     8  
   ╚  
   ╨  
   ╪  
   р     А     h     p  
   Ё  
   °  
      
        ╕     а     и  
     
      
   (  
   0     Ё     ╪     р  
   @  
   H  
   P  
   X     (	     	     	  
   h  
   p  
   x  
   А     `	     H	     P	  
   Р  
   Ш  
   а  
   и     Ш	     А	     И	  
   ╕  
   └  
   ╚  
   ╨     ╨	     ╕	     └	  
   р  
   ш  
   Ё  
   °     
     Ё	     °	  
     
     
     
         @
     (
     0
  
   0  
   8  
   @  
   H     x
     `
     h
  
   X  
   `  
   h  
   p     ф     э     Ў                     *     3     <     E     _     h     q     z     У     Ь     е     ┴     ╩     ╙     ▄     х     ю                 