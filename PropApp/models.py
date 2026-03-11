from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.timezone import now

user_roles = (
    ('Owner', 'Owner'),
    ('Tenant', 'Tenant'),
    ('Admin', 'Admin'),
    ('Agent', 'Agent'),
    ('Seller', 'Seller'),
)

property_status = (
    ('Available', 'Available'),
    ('Rented', 'Rented'),
)

property_type = (
    ('Apartment', 'Apartment'),
    ('House', 'House'),
    ('Commercial', 'Commercial'),
)

# ─── Sale Listing Choices ───
listing_type_choices = (
    ('sale', 'For Sale'),
    ('rent', 'For Rent'),
)

sale_property_type = (
    ('House', 'House'),
    ('Land', 'Land'),
    ('Apartment', 'Apartment'),
    ('Commercial', 'Commercial'),
    ('Villa', 'Villa'),
    ('Warehouse', 'Warehouse'),
)

sale_status_choices = (
    ('listed', 'Listed'),
    ('under_negotiation', 'Under Negotiation'),
    ('sold', 'Sold'),
    ('withdrawn', 'Withdrawn'),
)

offer_status_choices = (
    ('pending', 'Pending'),
    ('accepted', 'Accepted'),
    ('rejected', 'Rejected'),
    ('countered', 'Countered'),
    ('expired', 'Expired'),
)

visit_status_choices = (
    ('scheduled', 'Scheduled'),
    ('completed', 'Completed'),
    ('cancelled', 'Cancelled'),
    ('no_show', 'No Show'),
)

class User(AbstractUser):
    role = models.CharField(max_length=10, choices=user_roles, default='Tenant')

    def __str__(self):
        return self.username

class Owner(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100)
    phone_number = models.CharField(max_length=15)
    address = models.CharField(max_length=200)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='owner_profile')
    image = models.ImageField(upload_to='owner_images', blank=True)

    def __str__(self):
        return self.name

class Property(models.Model):
    name = models.CharField(max_length=100)
    address = models.CharField(max_length=200)
    types = models.CharField(max_length=10, choices=property_type)
    description = models.TextField()
    image = models.ImageField(upload_to='property_images', blank=True)
    number_of_units = models.IntegerField()
    status = models.CharField(max_length=20, choices=property_status, default='Available')
    price = models.IntegerField()
    owner = models.ForeignKey(Owner, on_delete=models.CASCADE, related_name='properties')
    date_added = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} at {self.address}"

class Unit(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='units')
    unit_number = models.IntegerField()
    bedrooms = models.IntegerField()
    bathrooms = models.IntegerField()
    rent = models.IntegerField()
    is_available = models.BooleanField(default=True)

    def __str__(self):
        return f"Unit {self.unit_number} in {self.property.name}"

class Tenant(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100)
    phone_number = models.CharField(max_length=15)
    address = models.CharField(max_length=200)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='tenant_profile')
    image = models.ImageField(upload_to='tenant_images', blank=True)

    def __str__(self):
        return self.name

class Lease(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='leases', null=True)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='leases')
    contract_details = models.TextField(blank=True, null=True)
    start_date = models.DateField()
    end_date = models.DateField()
    contract_accepted = models.BooleanField(default=False)
    contract_signed = models.BooleanField(default=False)
    contract_archived = models.BooleanField(default=False)
    rent_amount = models.IntegerField()

    class Meta:
        verbose_name_plural = "Leases"

    def get_status_display(self):
        if self.contract_accepted and self.contract_signed:
            return "Signed"
        elif self.contract_accepted:
            return "Accepted"
        else:
            return "Made"

class CustomerMessage(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_archived = models.BooleanField(default=False)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"Message from {self.name} ({self.email})"

class Updates(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    end_date = models.DateField()

    class Meta:
        verbose_name_plural = "Updates"

    def __str__(self):
        return self.title

class Email(models.Model):
    sender_email = models.EmailField(max_length=255, verbose_name="Sender's Email")
    recipient_email = models.EmailField(max_length=255, verbose_name="Recipient's Email")
    subject = models.CharField(max_length=255, verbose_name="Email Subject")
    body = models.TextField(verbose_name="Email Body")
    timestamp = models.DateTimeField(default=now, verbose_name="Received At")
    is_read = models.BooleanField(default=False, verbose_name="Read Status")

    def __str__(self):
        return f"Email from {self.sender_email} to {self.recipient_email}"

    class Meta:
        verbose_name_plural = "Emails"

class CustRequest(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='cust_requests')
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_archived = models.BooleanField(default=False)
    is_read = models.BooleanField(default=False)

class MaintenanceRequest(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='maint_requests')
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='maint_requests')
    title = models.CharField(max_length=100)
    description = models.TextField()
    request_date = models.DateTimeField(auto_now_add=True)
    completion_date = models.DateTimeField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=[
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed')
    ], default='open')

    def __str__(self):
        return f"{self.tenant.user.username} - {self.request_date}"
class Payment(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='payments')
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='payments')
    amount = models.IntegerField()
    date_paid = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return f"{self.tenant.user.username} - {self.date_paid}"
class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    content = models.TextField()
    sent_date = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"From {self.sender.username} to {self.recipient.username} - {self.sent_date}"
class Visit(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='visits')
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='visits')
    visit_date = models.DateTimeField(auto_now_add=True)
    description = models.TextField()
    def __str__(self):
        return f"{self.tenant.user.username} - {self.visit_date}"
class LikedProperties(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='liked_properties')
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='liked_by')
    total_likes = models.IntegerField(default=0)
    def __str__(self):
        return f"{self.user.username} - {self.property.name} - {self.total_likes} "


# ═══════════════════════════════════════════════════════════
#   REAL ESTATE MARKETPLACE — SALE LISTINGS / AGENTS / OFFERS
# ═══════════════════════════════════════════════════════════

class Agent(models.Model):
    """Real estate agent who visits, photographs, and negotiates properties."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='agent_profile')
    name = models.CharField(max_length=150)
    email = models.EmailField(max_length=150)
    phone_number = models.CharField(max_length=20)
    license_number = models.CharField(max_length=50, blank=True)
    bio = models.TextField(blank=True, help_text="Short biography / experience summary")
    specialization = models.CharField(max_length=100, blank=True, help_text="e.g. Residential, Commercial, Land")
    image = models.ImageField(upload_to='agent_images', blank=True)
    is_verified = models.BooleanField(default=False)
    rating = models.DecimalField(max_digits=3, decimal_places=2, default=0.00)
    total_deals = models.IntegerField(default=0)
    date_joined = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Agent: {self.name}"


class Seller(models.Model):
    """Person who lists houses/land for sale on the platform."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='seller_profile')
    name = models.CharField(max_length=150)
    email = models.EmailField(max_length=150)
    phone_number = models.CharField(max_length=20)
    address = models.CharField(max_length=250, blank=True)
    id_number = models.CharField(max_length=50, blank=True, help_text="National ID or passport")
    image = models.ImageField(upload_to='seller_images', blank=True)
    is_verified = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Seller: {self.name}"


class SaleProperty(models.Model):
    """A property listed for sale (houses, land, apartments, etc.)."""
    title = models.CharField(max_length=200)
    description = models.TextField()
    property_type = models.CharField(max_length=20, choices=sale_property_type)
    listing_type = models.CharField(max_length=10, choices=listing_type_choices, default='sale')
    price = models.DecimalField(max_digits=15, decimal_places=2, help_text="Asking price in Frw")
    negotiable = models.BooleanField(default=True)
    address = models.CharField(max_length=300)
    city = models.CharField(max_length=100, default='Kigali')
    district = models.CharField(max_length=100, blank=True)
    sector = models.CharField(max_length=100, blank=True)

    # Property details
    size_sqm = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True, help_text="Size in square meters")
    bedrooms = models.IntegerField(blank=True, null=True)
    bathrooms = models.IntegerField(blank=True, null=True)
    year_built = models.IntegerField(blank=True, null=True)
    has_title_deed = models.BooleanField(default=False)
    has_parking = models.BooleanField(default=False)
    has_garden = models.BooleanField(default=False)
    is_furnished = models.BooleanField(default=False)

    # Images (main + gallery)
    image = models.ImageField(upload_to='sale_property_images')
    image_2 = models.ImageField(upload_to='sale_property_images', blank=True)
    image_3 = models.ImageField(upload_to='sale_property_images', blank=True)
    image_4 = models.ImageField(upload_to='sale_property_images', blank=True)
    image_5 = models.ImageField(upload_to='sale_property_images', blank=True)
    video_url = models.URLField(blank=True, help_text="YouTube or video link for virtual tour")

    # Relationships
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE, related_name='sale_properties')
    assigned_agent = models.ForeignKey(Agent, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_properties')

    # Status
    status = models.CharField(max_length=20, choices=sale_status_choices, default='listed')
    is_featured = models.BooleanField(default=False)
    views_count = models.IntegerField(default=0)
    date_listed = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Sale Properties"
        ordering = ['-date_listed']

    def __str__(self):
        return f"{self.title} - {self.get_property_type_display()} ({self.get_status_display()})"


class Offer(models.Model):
    """An offer made by a buyer on a sale property, with negotiation."""
    sale_property = models.ForeignKey(SaleProperty, on_delete=models.CASCADE, related_name='offers')
    buyer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='offers_made')
    agent = models.ForeignKey(Agent, on_delete=models.SET_NULL, null=True, blank=True, related_name='offers_handled')
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    counter_amount = models.DecimalField(max_digits=15, decimal_places=2, blank=True, null=True)
    message = models.TextField(blank=True, help_text="Message to seller/agent")
    status = models.CharField(max_length=20, choices=offer_status_choices, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Offer {self.amount} Frw on {self.sale_property.title} by {self.buyer.username}"


class AgentAssignment(models.Model):
    """Track agent assignments to sale properties for site visits and negotiations."""
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='assignments')
    sale_property = models.ForeignKey(SaleProperty, on_delete=models.CASCADE, related_name='agent_assignments')
    assigned_date = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.agent.name} → {self.sale_property.title}"


class SiteVisit(models.Model):
    """Scheduled site visits by agents to inspect / photograph properties."""
    sale_property = models.ForeignKey(SaleProperty, on_delete=models.CASCADE, related_name='site_visits')
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='site_visits')
    visitor = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='booked_visits',
                                help_text="Buyer who requested the visit")
    scheduled_date = models.DateTimeField()
    status = models.CharField(max_length=20, choices=visit_status_choices, default='scheduled')
    notes = models.TextField(blank=True, help_text="Agent notes from the visit")
    report = models.TextField(blank=True, help_text="Detailed inspection report")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-scheduled_date']

    def __str__(self):
        return f"Visit: {self.sale_property.title} on {self.scheduled_date:%Y-%m-%d}"


class PropertyInquiry(models.Model):
    """Inquiry from a potential buyer about a sale property."""
    sale_property = models.ForeignKey(SaleProperty, on_delete=models.CASCADE, related_name='inquiries')
    name = models.CharField(max_length=150)
    email = models.EmailField(max_length=150)
    phone = models.CharField(max_length=20, blank=True)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Property Inquiries"

    def __str__(self):
        return f"Inquiry on {self.sale_property.title} from {self.name}"


class AgentReview(models.Model):
    """Review/rating for an agent from a buyer or seller."""
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='reviews')
    reviewer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='agent_reviews')
    rating = models.IntegerField(choices=[(i, i) for i in range(1, 6)])
    comment = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.reviewer.username} → {self.agent.name}: {self.rating}★"


# ─────────────────────────────────────────────────────────────
# Social Feed Models
# ─────────────────────────────────────────────────────────────

class Post(models.Model):
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='posts')
    content = models.TextField()  # Quill HTML
    location = models.CharField(max_length=200, blank=True)
    is_public = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    original_post = models.ForeignKey(
        'self', null=True, blank=True, on_delete=models.SET_NULL, related_name='reposts'
    )
    repost_comment = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.author.username}: {self.content[:60]}"

    def likes_count(self):
        return self.likes.count()

    def comments_count(self):
        return self.comments.filter(parent=None).count()

    def reposts_count(self):
        return self.reposts.count()

    def is_repost(self):
        return self.original_post is not None


class PostMedia(models.Model):
    MEDIA_TYPES = [('image', 'Image'), ('video', 'Video')]
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='media')
    file = models.FileField(upload_to='posts/media/')
    media_type = models.CharField(max_length=10, choices=MEDIA_TYPES, default='image')
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['order']

    def __str__(self):
        return f"{self.post_id} – {self.media_type} #{self.order}"


class Hashtag(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return f"#{self.name}"


class PostHashtag(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='post_hashtags')
    hashtag = models.ForeignKey(Hashtag, on_delete=models.CASCADE, related_name='post_hashtags')

    class Meta:
        unique_together = ('post', 'hashtag')

    def __str__(self):
        return f"{self.post_id} #{self.hashtag.name}"


class PostComment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='post_comments')
    guest_name = models.CharField(max_length=100, blank=True)
    guest_email = models.EmailField(blank=True)
    content = models.TextField()
    parent = models.ForeignKey(
        'self', null=True, blank=True, on_delete=models.CASCADE, related_name='replies'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        author = self.user.username if self.user else self.guest_name or 'Guest'
        return f"{author} on Post {self.post_id}"

    def display_name(self):
        if self.user:
            return self.user.get_full_name() or self.user.username
        return self.guest_name or 'Anonymous'


class PostLike(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='likes')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='post_likes')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('post', 'user')

    def __str__(self):
        return f"{self.user.username} ♥ Post {self.post_id}"


# ─────────────────────────────────────────────────────────────
# Notification Model
# ─────────────────────────────────────────────────────────────

class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('message', 'New Message'),
        ('like', 'Post Liked'),
        ('comment', 'New Comment'),
        ('repost', 'Post Reposted'),
        ('system', 'System'),
    ]
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    actor = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name='sent_notifications'
    )
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    message = models.CharField(max_length=300)
    link = models.CharField(max_length=300, blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"→ {self.recipient.username}: {self.message[:60]}"





