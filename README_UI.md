# CIDS-Mali — modernisation de l’interface utilisateur

## Ce qui a changé

- Le design est en français, blanc et professionnel, avec des dégradés subtils vert, jaune et rouge inspirés des couleurs du Mali.
- La structure Flask/Jinja2 est conservée : routes, champs de formulaire, token CSRF et variables existantes restent compatibles.
- Le système est pensé pour fonctionner hors ligne et sans dépendance externe.
- Les pages d’accueil, d’émission, de vérification et du tableau de bord ont été modernisées avec une approche responsive, accessible et légère.
- Les rôles sont distincts : le Directeur gère les comptes et les rapports; l’Administrateur gère les candidats et cartes; le Secrétaire vérifie et recherche uniquement.
- Les six catégories DEF, BAC, CAP, BT1, BT2 et IFM alimentent l’émission, la vérification et les rapports.
- La recherche filtrée, l’édition/réémission, la révocation, l’effacement, les exports CSV et le scan QR sont reliés aux routes protégées.

## Fichiers principaux

- [cids_mali/templates/base.html](cids_mali/templates/base.html)
- [cids_mali/templates/index.html](cids_mali/templates/index.html)
- [cids_mali/templates/login.html](cids_mali/templates/login.html)
- [cids_mali/templates/issue.html](cids_mali/templates/issue.html)
- [cids_mali/templates/verify.html](cids_mali/templates/verify.html)
- [cids_mali/templates/admin/dashboard.html](cids_mali/templates/admin/dashboard.html)
- [cids_mali/templates/admin/students.html](cids_mali/templates/admin/students.html)
- [cids_mali/templates/admin/student_detail.html](cids_mali/templates/admin/student_detail.html)
- [cids_mali/templates/admin/student_edit.html](cids_mali/templates/admin/student_edit.html)
- [cids_mali/templates/director/admins.html](cids_mali/templates/director/admins.html)
- [cids_mali/templates/director/settings.html](cids_mali/templates/director/settings.html)
- [cids_mali/static/css/main.css](cids_mali/static/css/main.css)
- [cids_mali/static/css/dashboard.css](cids_mali/static/css/dashboard.css)
- [cids_mali/static/js/main.js](cids_mali/static/js/main.js)
- [cids_mali/static/js/dashboard.js](cids_mali/static/js/dashboard.js)
- [cids_mali/static/img/hero-mali.svg](cids_mali/static/img/hero-mali.svg)

## Rapports

Le tableau de bord Director lit les statistiques depuis `GET /admin/api/stats`. Le rapport détaillé s’exporte en CSV depuis le dashboard. Les agrégats utilisent les données de cartes et les événements d’émission/vérification conservés dans SQLite.

## Personnalisation des couleurs

Les variables de palette sont définies en haut de [cids_mali/static/css/main.css](cids_mali/static/css/main.css). Modifier ces valeurs pour ajuster rapidement l’identité visuelle du projet.

## Bonnes pratiques

- La version actuelle reste compatible avec les routes Flask existantes.
- Aucun appel internet n’est requis au runtime.
- Les animations utilisent uniquement des transformations et de l’opacité.
- La navigation clavier et le contraste visuel ont été pris en compte.
- Le mode sombre est activable et enregistré dans `localStorage`.
