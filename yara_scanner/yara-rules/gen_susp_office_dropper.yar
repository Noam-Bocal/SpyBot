YARAЦ          ж       └  f      └  &         &         >        D        b      М   ю         ю"         ю*         ю/                                                                                           ^             а                                 К             `     °                           Х             @     ╕                           ╞                   `                           е                   x                           ж             р     ш             ····················································   $      0                     w      ~                     Э      з                     ╣      ╛                     ╔      ╠                    $      |                    w      ~                     Э      з                     ╣      ╟                    ╥     ╪                    ╔                         $      й                    w      ~                     Э      з                     ╣      ╟                    ∙          <                 ╥     ╪                    ╔                          $      ╡                    w      ~                     Э      ю                    ╣      -                    ∙          F                 ╥     8                    ╔      y                   $      с                    w      ~                     Э      з                     ╣      -                    ∙          <                 ╥     8                    ╔      .                   $      ┼                    w      є                    Э      ¤                    ╣      :                    E     N                    ∙          7                 ╔      Y                   $      ╟                    w                          ╣                          ∙          A                 ╥                         Э      ]                    ╔      Ы                       ┌║·┌║·           ї                      ё   Й      ┌║·┌║·                                  Й      ┌║·┌║·                                  Й      ┌║·┌║·           8                     4  Й      ┌║·┌║·           M                     I  Й      ┌║·┌║·          B                     >  Й      ┌║·┌║·          U                     Q  Й      ┌║·┌║·          h                     d  Й      ┌║·┌║·          {                     w  	  	    ┌║·┌║·          $                     ё   	  
    ┌║·┌║·          ;                     7  Й      ┌║·┌║·          E                     A  С      ┌║·┌║·    	      _                     [  Й      ┌║·┌║·          i                       Й      ┌║·┌║·          q                       Й      ┌║·┌║·                               4  Й      ┌║·┌║·          И                     I  	      ┌║·┌║·          Ю                       	      ┌║·┌║·          м                       	      ┌║·┌║·          ╣                     4        ┌║·┌║·          S                       	      ┌║·┌║·          s                       	      ┌║·┌║·          q                     ё   	      ┌║·┌║·          О                     7  Й      ┌║·┌║·          Ь                     A  	      ┌║·┌║·          Г                     ~  	      ┌║·┌║·          Н                     И  KД                     ╠                     └  Й      ┌║·┌║·          ╒                       K      ┌║·┌║·                                   █  K      ┌║·┌║·                                   ы  K     ┌║·┌║·                                   √      ····················default SUSP_Office_Dropper_Strings description Detects Office droppers that include a notice to enable active content author Florian Roth (Nextron Systems) reference Internal Research date 2018-09-13 id 6560fdf7-46e8-5c16-8263-a36f1dec7868 $a1 _VBA_PROJECT $s1 click enable editing $s2 click enable content $s3 "Enable Editing" $s4 "Enable Content" SUSP_EnableContent_String_Gen Detects suspicious string that asks to enable active content in Office Doc 2019-02-12 hash1 525ba2c8d35f6972ac8fcec8081ae35f6fe8119500be20a4113900fe57d6a0de d763bc21-2925-55df-85e0-1ee857e921ca $e1 Enable Editing $e2 Enable Content $e3 Enable editing $e4 Enable content SUSP_WordDoc_VBA_Macro_Strings Detects suspicious strings in Word Doc that indcate malicious use of VBA macros score 210baf6e-ec67-5bc4-ba27-6a6de0c11a73 \Microsoft Shared\ $a2 \VBA\ $a3 Microsoft Office Word $a4 PROJECTwm AppData Document_Open Project1 CreateObject SUSP_OfficeDoc_VBA_Base64Decode Detects suspicious VBA code with Base64 decode functions https://github.com/cpaton/Scripting/blob/master/VBA/Base64.bas 2019-06-21 52262bb315fa55b7441a04966e176b0e26b7071376797e35c80aa60696b6d6fc 99690116-fc89-53d7-8f29-575d75d53fc9 B64_CHAR_DICT Base64Decode Base64Encode SUSP_VBA_FileSystem_Access Detects suspicious VBA that writes to disk and is activated on document open 91241b91-ca3f-5817-bf78-550fe015b467 \Common Files\Microsoft Shared\ Scripting.FileSystemObject WScript.Shell AutoOpen SUSP_Excel_IQY_RemoteURI_Syntax Detects files with Excel IQY RemoteURI syntax Nick Carr https://twitter.com/ItsReallyNick/status/1030330473954897920 2018-08-17 modified 2023-11-25 ea3427da-9cce-5ad9-9c78-e3cee802ba80 $URL http $fp1 https://go.microsoft.com SUSP_Macro_Sheet_Obfuscated_Char Finding hidden/very-hidden macros with many CHAR functions DissectMalware 2020-04-07 0e9ec7a974b87f4c16c842e648dd212f80349eecb4e636087770bc1748206c3b https://twitter.com/DissectMalware/status/1247595433305800706 791e9bba-3e4e-5efd-a800-a612c6f92cfb $ole_marker ╨╧рб▒с Excel $macro_sheet_h1 $macro_sheet_h2 $char_func l       ? Ї@╨╧d/   %A ╨ f/          /6   ?B   8      p      и      р                   г      ? Ї@╨╧d/К   ? @╕     1   ? @╕   P  1   ? @╕   И  1   ? @╕   └  16   ?B        P     И     └                       ? Ї@╨╧d/   %A А f/Y   BB   °     0     h     а     ╪          H     А                 Q      ? Ї@╨╧d/   %@ Ёf/-   ?B   ╕     Ё     (                 v      ? Ї@╨╧d/   %A Р f/#   BB   `     Ш          /-   ?B   ╨          @                 c      ? їAWEBd/   ?їA
1
d/   %A   f/      x  /   ?B   ░                 e      ?    ш  /$   ?B   X     Р          /      ╚  ?
g/                 вЕв ааааааввнвваааааав вЕнвЕв ааааааввнвваааааав вЕнвааааааааааааааааааааааааавв=в вAвoв нв вoвAв в=вааааааааааааааааааааааааавн        
            0  <                                                  h      V       
          t      n   
                #"               $                                        p           .                                  $  >8          B  C  D  7L  F.                           N     0 Q&            EZ      Fj             5z      ]*  7А      `4      P Nb          f$  ;Р      i  j  /╩  W`  m2      DЮ  /╨  q   fN  Cд  t  5▄  dR  j\  0 B┤  oJ  2
 qH   4  uB      vD  oT  sP  jl  tX      of  SЦ   4                  hВ  f|  bФ  y^  W┬  dЪ  dи  B8 bм  ur  uv      ux  d░  jж     `·  uТ  uО  b■   Ъ   $      o▓   м      `         q╛  p╚                                              dB     cF fD bJ             u s             lL                                                 ╤                          ╨@                                                                                                                                                                                                                                                                  с╕                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
      	                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         8                                     p                   
   (             и                                     р                   
   x                                                 P                  
   ╚             И                  
   Ё             └                  
               °                                    0                                    h                                    а                                    ╪                                                              	          H                                    А                                    ╕                                    Ё                                    (                  
   ╨            `                                    Ш                          
          ╨                  
   0  	                                              @                                    x                                    ░                                    ш                                                                         X     
                           Р     (      1                     ╚     W      p                                                   (             0                          (      @      H      `      h      А      И      0                
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
   ╕      #      6      ?      H      Q      H      P      `      X      h      а      и      └      ╚      р      ш                       (     @     H     H     0     8  
   ╚   
   ╨   
   ╪   
   р      А     h     p  
   Ё   
   °   
      
        ╕     а     и  
     
      
   (  
   0     Ё     ╪     р  
   @  
   H  
   P  
   X     З      Ы      ░      ┼      ╪      с      ъ      є      А      И      Ш      Р      а      `     h     А     И     а     и     └     ╚     р     ш                      (     (            
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
   ╨     ╨     ╕     └  
   р  
   ш  
   Ё  
   °          Ё     °  
     
     
     
         @     (     0  
   0  
   8  
   @  
   H     x     `     h  
   X  
   `  
   h  
   p     ░     Ш     а  
   А  
   И  
   Р  
   Ш     4     =     F     O     X     a     j     s     ╕      └      ╨      ╚      ╪      @     H     `     h     А     И     а     и     └     ╚     р     ш                ш     ╨     ╪  
   и  
   ░  
   ╕  
   └                  
   ╨  
   ╪  
   р  
   ш     X     @     H  
   °  
      
     
        ▓     ╗     ─     Ё      °                            (     @     H     `     h     А     И     а     и     └     ╚     р     ш     Р     x     А  
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
   ╪               (     1     :     (     0     @     8     H                      (     @     H     `     h     А     И     а     и     └     ╚     и     Р     Ш  
   ш  
   Ё  
   °  
         р     ╚     ╨  
     
     
      
   (     Й     Ь     `     h     x     p     А     р     ш                      (     @     H     `     h     А     И     а     и                  
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
   ╚     °     р     ш  
   ╪  
   р  
   ш  
   Ё     ─     ╓     ▀     ў     
  