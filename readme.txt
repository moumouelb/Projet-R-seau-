graphic_interface.py:
création d'une fenêtre, grâce à la bibliothèque tkinter, qui contient un menubar 
en cascade via lequel on peut ouvrir un fichier et fermer le programme.
cette fenêtre contient deux "frames", celle de gauche contient des boutons
(chacune représente une trame) cliquables, quand on clique sur un bouton 
la fonction extract_trame qui renvoie la trame "clean" et la fonction tree qui 
fait l'affichage sous forme arborescente de l'analyse de la trame dans la "frame" de droite.

extraction.py:
test-offset: cette fonction retourne un booléen qui indique si l'offset donné est valide
ou pas.
extract_line: cette fonction parcourt le tableau qui contient les élements de la ligne, 
elle met premièrement dans un autre tableau temporaire en ignorant les éléments invalides
(qui ne sont  pas sous la forme de deux chiffres hexadécimaux).
on extrait de ce tableau n éléments(avec n égale à la différence deds offsets).
si n est supérieure à la longueur de notre tableau, la fonction retourne une erreur 
en indiquant sa ligne.
last_line: retourne la dernière ligne autrement dit elle ignore le texte qui se trouve 
entre deux trames.
no_empty: elle ignore les lignes vides qui se trouvent dans la trame.
extract_final_line: elle fait la même chose que extract_line sauf que elle extrait tous 
les éléments de la dernière ligne vu qu'on a pas d'offset après pour avoir une différence 
avec laquelle on fait l'extraction habituelle.
extract_trame: elle fait appel aux fonctions précédentes pour faire l'extraction ligne par 
ligne des éléments(octets) dans un tableau en utilisant une boucle for, en sortant de la boucle
on fait l'extraction de la dernière ligne.

analyse.py:
tree: tout d'abord elle vérifie si la trame contient une erreur ou pas et elle l'affiche 
si la trame ne contient pas d'erreur, on utilise le total length de l'entête ip auquel
on ajoute 14 de l'entête ethernet pour connaitre la fin de la trame.
elle fait l'appel des fonctions Ethernet, Datagram_UDP, Datagram_IP, DHCP et DNS qui renvoient
chacune un tableau qui contient l'analyse à afficher, cet affichage se fait sous forme 
arborescente.
Ethernet: elle renvoie dans un tableau le contenu de l'entête Ethernet.
Datagram_IP: elle renvoie dans un tableau le contenu de l'entête IP, grâce à la case IHL
on sait si l'entête contient des options ou pas ainsi on sait quoi renvoyer exactement dans le 
tableau.
Datagram_UDP: elle renvoie dans un tableau le contenu de l'entête UDP.
tds: elle prend en argument une chaine hexadécimale et un coefficient et renvoie une chaine décimale
multipliée par ce coefficient.
tostring: elle convertit un entier en chaine de caractères.
hex_to_ascii: elle convertit une chaine hexadécimale en chaine de caractères.
lc: compteur de label
DHCP: elle renvoie dans un tableau le contenu de l'entête DHCP.
DNS:elle renvoie dans un tableau le contenu de l'entête DNS.
resource_records: elle traite les réponses de DNS selon leur type en exploitant des dictionnaires qui contiennent
les noms des types et des classes et un dictionnaire vide qui se remplit au fûr et à mesure par 
les noms des réponses et questions
   



