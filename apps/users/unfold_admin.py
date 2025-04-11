from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone
from datetime import timedelta
from unfold.widgets import TALL # Or SHORT, FULL
from unfold.charts import Chart # Import Chart component
from .models import User # Import your User model

# Make sure this function path matches UNFOLD["DASHBOARD_CALLBACK"] in settings.py
def dashboard_callback(request):
    """
    Callback function to generate dashboard components for Django Unfold.
    """
    components = []

    # --- Example 1: User Signup Trend Chart (Last 30 days) ---
    today = timezone.now().date()
    start_date = today - timedelta(days=30)

    user_signups = (
        User.objects.filter(date_joined__date__gte=start_date)
        .annotate(signup_date=TruncDate("date_joined"))
        .values("signup_date")
        .annotate(count=Count("id"))
        .order_by("signup_date")
    )

    # Prepare data for Chart.js (labels and data points)
    signup_labels = [(start_date + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(31)]
    signup_data_dict = {item['signup_date'].strftime("%Y-%m-%d"): item['count'] for item in user_signups}
    signup_counts = [signup_data_dict.get(label, 0) for label in signup_labels]

    # Add Chart component
    components.append(
         Chart(
             title="User Signups (Last 30 Days)",
             data={
                 "labels": signup_labels,
                 "datasets": [
                     {
                         "label": "New Users",
                         "data": signup_counts,
                         "borderColor": "rgb(75, 192, 192)", # Example color
                         "tension": 0.1, # Makes the line slightly curved
                         "fill": False,
                     }
                 ],
             },
             # Chart type can be 'line', 'bar', 'pie', etc.
             # See Chart.js docs: https://www.chartjs.org/docs/latest/
             chart_type="line",
             width=TALL, # Adjust width/height: SHORT, TALL, FULL
        )
    )

    # --- Example 2: User Verification Status Pie Chart ---
    verification_status = (
        User.objects.values("is_verified")
        .annotate(count=Count("id"))
        .order_by("is_verified")
    )

    verified_count = 0
    unverified_count = 0
    for status in verification_status:
        if status["is_verified"]:
            verified_count = status["count"]
        else:
            unverified_count = status["count"]

    components.append(
        Chart(
            title="User Verification Status",
            data={
                "labels": ["Verified", "Not Verified"],
                "datasets": [
                    {
                        "label": "User Status",
                        "data": [verified_count, unverified_count],
                        "backgroundColor": [
                            "rgba(75, 192, 192, 0.5)", # Verified color
                            "rgba(255, 99, 132, 0.5)", # Not Verified color
                        ],
                        "borderColor": [
                            "rgb(75, 192, 192)",
                            "rgb(255, 99, 132)",
                        ],
                        "borderWidth": 1,
                    }
                ],
            },
            chart_type="pie", # Pie chart
            width=TALL,
        )
    )

    # Add more components (tables, values, etc.) as needed
    # Example: from unfold.widgets import Value
    # total_users = User.objects.count()
    # components.append(Value(label="Total Users", value=total_users, url=reverse("admin:your_user_app_user_changelist")))


    return components # Return the list of components