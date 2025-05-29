from dash import Output, Input, State, no_update, html
import subprocess
from io import StringIO
from model.flowcapture import run_capture
from data.fetch_data import load_raw_network_traffic, load_processed_network_traffic, get_packet_summary, load_sample_prediction
# Thêm các import cần thiết
from data.database import engine, prediction_results
import dash_bootstrap_components as dbc
from sqlalchemy import select, bindparam  # Thêm import cho select và bindparam

def network_flow_callbacks(app):
    from app.pages.dashboard import create_dashboard
    
    @app.callback(
        [Output("processed-traffic-table", "data"),
         Output('initial-traffic-table', 'data'),
         Output('sample-prediction-table', 'data'),
         Output('packet-count', 'children'),
         Output('total-bytes', 'children'),
         Output('lost-packets', 'children'),
         Output('duration', 'children')],
        [Input("start-button", "n_clicks")],
        [
            State("interface-input", "value"),
            State("time-input", "value"),
            State("session-store", "data"),
        ],
        prevent_initial_call=True
    )
    def handle_network_flow_collection(n_clicks, interface, time_range, session_data):
        if n_clicks is None or not interface or not time_range:
            return [no_update] * 7
        
        try:
            time_seconds = int(time_range)
        except ValueError:
            return [no_update] * 7
        
        try:
            run_capture(interface, time_seconds)
            df_processed = load_processed_network_traffic()
            df_raw = load_raw_network_traffic()
            df_sample = load_sample_prediction()

            data = get_packet_summary()
            if not data:
                return [no_update] * 7

            total_flows = data['total_flows']
            total_bytes = data['total_bytes']
            lost = data['lost']
            capture_duration = data['capture_duration']
            
            return (
                df_processed.to_dict('records'),
                df_raw.to_dict('records'),
                df_sample.to_dict('records'),
                str(total_flows),
                total_bytes,
                lost,
                str(capture_duration)
            )
        except Exception as e:
            print("Error during capture:", e)
            return [no_update] * 7

    # Thêm callback cho Detection Results
    @app.callback(
        Output('detection-results', 'children'),
        Input('sample-prediction-table', 'active_cell'),
        State('sample-prediction-table', 'data')
    )
    def update_detection_results(active_cell, data):
        if active_cell:
            row = active_cell['row']
            selected_sample = data[row]
            sample_index = selected_sample['sample_index']
            
            # Truy vấn cơ sở dữ liệu để lấy kết quả phát hiện cho sample_index
            conn = engine.connect()
            query = select(prediction_results).where(prediction_results.c.sample_index == bindparam('sample_idx'))
            results = conn.execute(query, {'sample_idx': sample_index}).fetchall()
            conn.close()
            
            # Tạo danh sách các cảnh báo
            alerts = []
            for result in results:
                color = "success" if result.label == "Benign" else "danger"  # Xanh lá cho Benign, đỏ cho Malicious
                alerts.append(
                    dbc.Alert(
                        [
                            html.H6(f"Alert: {result.label}", className="alert-heading"),
                            html.P([html.Span("Attack Type: ", className="fw-bold"), result.attack_type], className="mb-0"),
                            html.P([html.Span("Attack Tool: ", className="fw-bold"), result.attack_tool], className="mb-0"),
                            html.P([html.Span("Timestamp: ", className="fw-bold"), result.time], className="mb-0"),
                        ],
                        color=color,
                        className="mb-2",
                    )
                )
            return alerts
        return "Vui lòng chọn một mẫu để xem kết quả phát hiện."