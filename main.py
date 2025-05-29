import dash
from dash import dcc, html
import dash_bootstrap_components as dbc
from app.pages import login, dashboard
from app.callbacks import login_callbacks, dashboard_callbacks


# CSS bên ngoài
external_stylesheets = [
    dbc.themes.BOOTSTRAP,
    dbc.themes.SANDSTONE,
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css'
]

# Tạo ứng dụng Dash
app = dash.Dash(__name__, external_stylesheets=external_stylesheets, suppress_callback_exceptions=True)
app.title = '5G Dashboard'
server = app.server

# Template HTML và CSS tùy chỉnh
app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: #333;
        }

        .container {
            width: 100%;
            max-width: 450px;
            padding: 40px;
        }

        .login-box {
            background-color: rgba(255, 255, 255, 0.9);
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }

        .login-header {
            padding: 25px;
            background-color: #0078d7;
            color: white;
            text-align: center;
        }

        .login-header h2 {
            font-size: 24px;
            font-weight: 500;
        }

        .login-header .logo {
            margin-bottom: 15px;
        }

        .login-form {
            padding: 30px;
        }

        .form-group {
            margin-bottom: 20px;
            position: relative;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #444;
            font-weight: 500;
        }

        .form-control {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            transition: all 0.3s;
        }

        .form-control:focus {
            border-color: #0078d7;
            outline: none;
            box-shadow: 0 0 0 2px rgba(0, 120, 215, 0.2);
        }

        .password-toggle {
            position: absolute;
            right: 10px;
            top: 25px;
            cursor: pointer;
            color: #666;
        }

        .btn {
            background-color: #0078d7;
            color: white;
            border: none;
            border-radius: 5px;
            padding: 12px;
            width: 100%;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.3s;
        }

        .btn:hover {
            background-color: #005fa3;
        }

        .checkbox-container {
            display: flex;
            align-items: center;
        }

        .checkbox-container input {
            margin-right: 5px;
        }

        .forgot-link {
            color: #0078d7;
            text-decoration: none;
        }

        .forgot-link:hover {
            text-decoration: underline;
        }

        .server-status {
            margin-top: 15px;
            padding: 10px;
            background-color: #f5f5f5;
            border-radius: 5px;
            font-size: 14px;
            text-align: center;
        }

        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            background-color: #4CAF50;
            border-radius: 50%;
            margin-right: 10px;
        }
        .status-text {
            display: flex;
            align-items: center;
        }
        .datetime {
            font-size: 14px;
            color: #555;
        }

        @media (max-width: 480px) {
            .container {
                padding: 20px;
            }
            
            .login-form {
                padding: 20px;
            }
        }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
'''

# Layout chính
app.layout = html.Div([
    dcc.Location(id='url', refresh=True),
    dcc.Store(id='session-store', storage_type='session'),
    html.Div(id='page-content')
])

# Đăng ký callback
login_callbacks.register_callbacks(app)
dashboard_callbacks.network_flow_callbacks(app)

if __name__ == '__main__':
    app.run(debug=True, port=8111)