import logging
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)

# WCAG 2.0 AA requires a contrast ratio of at least 4.5:1 for normal text
# and 3:1 for large text
MIN_CONTRAST_RATIO = 4.5

def calculate_luminance(color: Tuple[int, int, int]) -> float:
    """
    Calculate the relative luminance of a color.
    
    Args:
        color: RGB color tuple (r, g, b) with values 0-255
        
    Returns:
        float: Relative luminance value (0-1)
    """
    r, g, b = [c / 255.0 for c in color]
    
    # Convert to sRGB
    r = r / 12.92 if r <= 0.03928 else ((r + 0.055) / 1.055) ** 2.4
    g = g / 12.92 if g <= 0.03928 else ((g + 0.055) / 1.055) ** 2.4
    b = b / 12.92 if b <= 0.03928 else ((b + 0.055) / 1.055) ** 2.4
    
    # Calculate luminance
    return 0.2126 * r + 0.7152 * g + 0.0722 * b

def calculate_contrast_ratio(fg_color: Tuple[int, int, int], bg_color: Tuple[int, int, int]) -> float:
    """
    Calculate the contrast ratio between two colors.
    
    Args:
        fg_color: Foreground RGB color tuple (r, g, b)
        bg_color: Background RGB color tuple (r, g, b)
        
    Returns:
        float: Contrast ratio (1-21)
    """
    l1 = calculate_luminance(fg_color)
    l2 = calculate_luminance(bg_color)
    
    # Ensure l1 is the lighter color
    if l1 < l2:
        l1, l2 = l2, l1
    
    # Calculate contrast ratio
    return (l1 + 0.05) / (l2 + 0.05)

def is_accessible_color_pair(fg_color: Tuple[int, int, int], bg_color: Tuple[int, int, int]) -> bool:
    """
    Check if a color pair meets WCAG 2.0 AA contrast requirements.
    
    Args:
        fg_color: Foreground RGB color tuple (r, g, b)
        bg_color: Background RGB color tuple (r, g, b)
        
    Returns:
        bool: True if accessible
    """
    ratio = calculate_contrast_ratio(fg_color, bg_color)
    return ratio >= MIN_CONTRAST_RATIO

def get_accessible_color_scheme() -> Dict[str, Dict[str, Tuple[int, int, int]]]:
    """
    Get an accessible color scheme for reports.
    
    Returns:
        dict: Color scheme with accessible color pairs
    """
    return {
        "light": {
            "background": (255, 255, 255),
            "text": (33, 37, 41),
            "primary": (0, 123, 255),
            "secondary": (108, 117, 125),
            "success": (40, 167, 69),
            "danger": (220, 53, 69),
            "warning": (255, 193, 7),
            "info": (23, 162, 184)
        },
        "dark": {
            "background": (33, 37, 41),
            "text": (248, 249, 250),
            "primary": (0, 123, 255),
            "secondary": (108, 117, 125),
            "success": (40, 167, 69),
            "danger": (220, 53, 69),
            "warning": (255, 193, 7),
            "info": (23, 162, 184)
        }
    }

def add_accessibility_features_to_html(html: str) -> str:
    """
    Add accessibility features to HTML report.
    
    Args:
        html: HTML content
        
    Returns:
        str: HTML with accessibility features
    """
    # Add lang attribute to html tag
    html = html.replace("<html>", "<html lang=\"en\">")
    
    # Add ARIA roles
    html = html.replace("<div class=\"container\">", "<div class=\"container\" role=\"main\">")
    html = html.replace("<div class=\"section\">", "<div class=\"section\" role=\"region\">")
    
    # Add skip link for keyboard navigation
    skip_link = """<a href="#main-content" class="skip-link">Skip to main content</a>
    <style>
        .skip-link {
            position: absolute;
            top: -40px;
            left: 0;
            background: #000;
            color: white;
            padding: 8px;
            z-index: 100;
        }
        .skip-link:focus {
            top: 0;
        }
    </style>
    """
    html = html.replace("<body>", f"<body>\n    {skip_link}")
    
    # Add id for skip link target
    html = html.replace("<div class=\"container\">", "<div id=\"main-content\" class=\"container\">")
    
    # Add keyboard navigation for tables
    html = html.replace("<table>", "<table role=\"grid\" tabindex=\"0\">")
    html = html.replace("<th>", "<th role=\"columnheader\" tabindex=\"0\">")
    html = html.replace("<td>", "<td role=\"gridcell\" tabindex=\"0\">")
    
    # Add alt text to images
    html = html.replace("<img src=", "<img alt=\"Visualization chart\" src=")
    
    return html
