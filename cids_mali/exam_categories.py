"""Official examination categories used by issued student cards."""

EXAM_CATEGORIES = {
    "DEF": "Diplôme d'Études Fondamentales",
    "BAC": "Baccalauréat",
    "CAP": "Certificat d'Aptitude Professionnelle",
    "BT1": "Brevet de Technicien 1re Partie",
    "BT2": "Brevet de Technicien 2e Partie",
    "IFM": "Institut de Formation des Maîtres",
}

EXAM_CATEGORY_CHOICES = [
    (code, f"{code} - {label}")
    for code, label in EXAM_CATEGORIES.items()
]
