from django.db import models
import uuid


class AbstractBaseModel(models.Model):
    """
    Abstract base model.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True,
                                   help_text="Date and time when this entry was "
                                             "created in the system")
    updated_at = models.DateTimeField(auto_now=True,
                                   help_text="Date and time when the table data was "
                                             "last updated in the system")

    # ---------------------------------------------------------------------------
    # Meta
    # ---------------------------------------------------------------------------
    class Meta:
        abstract = True
