"""CSRF-protected forms used by the web interface."""

from datetime import UTC, datetime

from flask_wtf import FlaskForm
from wtforms import BooleanField, FileField, IntegerField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, NumberRange, Optional, Regexp

from cids_mali.exam_categories import EXAM_CATEGORY_CHOICES


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=256)])
    submit = SubmitField("Sign in")


class IssueForm(FlaskForm):
    first_name = StringField("First name", validators=[DataRequired(), Length(max=80)])
    last_name = StringField("Last name", validators=[DataRequired(), Length(max=80)])
    date_of_birth = StringField("Date of birth", validators=[DataRequired(), Regexp(r"^\d{4}-\d{2}-\d{2}$")])
    student_class = StringField("Class", validators=[DataRequired(), Length(max=120)])
    school = StringField("School", validators=[DataRequired(), Length(max=120)])
    exam_category = SelectField(
        "Examen national",
        choices=EXAM_CATEGORY_CHOICES,
        validators=[DataRequired()],
    )
    nina = StringField("NINA (optional)", validators=[Optional(), Length(max=32)])
    guardian_name = StringField("Guardian name", validators=[DataRequired(), Length(max=120)])
    consent_date = StringField(
        "Consent date",
        default=lambda: datetime.now(UTC).date().isoformat(),
        validators=[DataRequired(), Regexp(r"^\d{4}-\d{2}-\d{2}$")],
    )
    consent_given = BooleanField("Parental consent recorded", validators=[DataRequired()])
    photo = FileField("Student photo", validators=[DataRequired()])
    submit = SubmitField("Issue card")


class EditIssueForm(IssueForm):
    photo = FileField("Student photo (optional)", validators=[Optional()])


class AdminUserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField("Temporary password", validators=[DataRequired(), Length(min=12, max=256)])
    secretary = BooleanField("Secretary role")
    submit = SubmitField("Create user")


class CreateAdminForm(FlaskForm):
    username = StringField("Nom d’utilisateur", validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField("Mot de passe temporaire", validators=[DataRequired(), Length(min=12, max=256)])
    role = SelectField(
        "Rôle",
        choices=[("admin", "Administrateur"), ("secretary", "Secrétaire")],
        validators=[DataRequired()],
    )
    submit = SubmitField("Créer le compte")


class DirectorSettingsForm(FlaskForm):
    card_validity_days = IntegerField(
        "Durée de validité des cartes (jours)",
        validators=[DataRequired(), NumberRange(min=30, max=730)],
    )
    submit = SubmitField("Enregistrer les paramètres")


class ActionForm(FlaskForm):
    student_id = StringField("Student ID", validators=[DataRequired(), Length(max=36)])
    reason = StringField("Reason", validators=[Optional(), Length(max=240)])
    submit = SubmitField("Submit")