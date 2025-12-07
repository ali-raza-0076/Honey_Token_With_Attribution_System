"""
Visualization Dashboard for Cloud Honey Tokens
Real-time attack monitoring and analytics
"""

import os
from datetime import datetime, timedelta
from dash import Dash, html, dcc, Input, Output
import plotly.graph_objs as go
import plotly.express as px
from dotenv import load_dotenv
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import os
import sys
from datetime import datetime, timedelta
from dash import Dash, html, dcc, Input, Output
import plotly.graph_objs as go
import plotly.express as px
from dotenv import load_dotenv
import boto3
from decimal import Decimal

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analysis.cloudwatch_analyzer import CloudWatchAnalyzer

load_dotenv()

app = Dash(__name__, title="Cloud Honey Tokens Dashboard")

region = os.getenv('AWS_REGION', 'us-east-1')

try:
    analyzer = CloudWatchAnalyzer(region=region)
except Exception as e:
    print(f"Warning: Could not initialize analyzer: {e}")
    analyzer = None

app.layout = html.Div([
    html.Div([
        html.Div([
            html.H1("Cloud Honey Token & Auto Attribution System", 
                    style={'margin': 0, 'color': '#1a1a1a'}),
            html.P("Real-time Security Monitoring Dashboard",
                   style={'margin': '5px 0 0 0', 'color': '#666666'})
        ], style={'flex': '1'}),
        html.Div([
            html.Span(f"Region: {region}", 
                     style={'color': '#666666', 'marginRight': '20px'}),
            html.Span("● Live", 
                     style={'color': '#28a745', 'fontSize': '14px'})
        ], style={'display': 'flex', 'alignItems': 'center'})
    ], style={
        'display': 'flex',
        'justifyContent': 'space-between',
        'alignItems': 'center',
        'padding': '25px 40px',
        'backgroundColor': '#ffffff',
        'borderBottom': '1px solid #e0e0e0'
        'marginBottom': '0'
    }),
    
    dcc.Interval(
        id='interval-component',
        interval=60*1000,
        n_intervals=0
    ),
    
    html.Div([
        html.Div([
            html.Label('Time Range', style={'fontSize': '13px', 'fontWeight': '500', 'color': '#1a1a1a'}),
            dcc.Dropdown(
                id='time-range',
                options=[
                    {'label': 'Last Hour', 'value': 1},
                    {'label': 'Last 6 Hours', 'value': 6},
                    {'label': 'Last 24 Hours', 'value': 24},
                    {'label': 'Last Week', 'value': 168},
                ],
                value=24,
                style={'width': '200px'},
                clearable=False
            ),
        ], style={'marginRight': '20px'}),
        html.Button('Refresh Data', id='refresh-button', n_clicks=0,
                   style={
                       'padding': '10px 24px',
                       'backgroundColor': '#007bff',
                       'color': 'white',
                       'border': 'none',
                       'borderRadius': '6px',
                       'cursor': 'pointer',
                       'fontSize': '14px',
                       'fontWeight': '500',
                       'transition': 'all 0.2s',
                       'marginTop': '23px'
                   })
    ], style={
        'display': 'flex',
        'alignItems': 'flex-end',
        'padding': '25px 40px',
        'backgroundColor': '#ffffff',
        'borderBottom': '1px solid #e0e0e0'
    }),
    
    html.Div(id='summary-cards', style={'padding': '30px 40px'}),
    
    html.Div([
        html.Div([
            html.Div([
                dcc.Graph(id='events-timeline')
            ], className='chart-container'),
            
            html.Div([
                dcc.Graph(id='severity-distribution')
            ], className='chart-container'),
        ], style={'display': 'grid', 'gridTemplateColumns': '2fr 1fr', 'gap': '24px', 'marginBottom': '24px'}),
        
        html.Div([
            html.Div([
                dcc.Graph(id='top-attackers')
            ], className='chart-container'),
            
            html.Div([
                dcc.Graph(id='attack-types')
            ], className='chart-container'),
        ], style={'display': 'grid', 'gridTemplateColumns': '1fr 1fr', 'gap': '24px', 'marginBottom': '24px'}),
        
        html.Div([
            html.Div([
                dcc.Graph(id='hourly-pattern')
            ], className='chart-container'),
            
            html.Div([
                dcc.Graph(id='resource-access')
            ], className='chart-container'),
        ], style={'display': 'grid', 'gridTemplateColumns': '1fr 1fr', 'gap': '24px', 'marginBottom': '24px'}),
    ], style={'padding': '0 40px'}),
    
    html.Div([
        html.H3("Recent Security Events", 
               style={'fontSize': '18px', 'fontWeight': '600', 'color': '#1a1a1a'}),
        html.Div(id='recent-events-table')
    ], style={'padding': '30px 40px', 'marginTop': '10px'}),
    
], style={
    'fontFamily': '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
    'backgroundColor': '#f5f5f5',
    'minHeight': '100vh',
    'margin': 0
})


@app.callback(
    [Output('summary-cards', 'children'),
     Output('events-timeline', 'figure'),
     Output('severity-distribution', 'figure'),
     Output('top-attackers', 'figure'),
     Output('attack-types', 'figure'),
     Output('hourly-pattern', 'figure'),
     Output('resource-access', 'figure'),
     Output('recent-events-table', 'children')],
    [Input('time-range', 'value'),
     Input('refresh-button', 'n_clicks'),
     Input('interval-component', 'n_intervals')]
)
def update_dashboard(hours, n_clicks, n_intervals):
    """Update all dashboard components"""
    
    if analyzer is None:
        return (
            html.Div("Dashboard not configured. Please set GCP_PROJECT_ID in .env", 
                    style={'textAlign': 'center', 'color': 'red', 'padding': '50px'}),
            go.Figure(), go.Figure(), go.Figure(), go.Figure(), go.Figure(), go.Figure(),
            html.Div()
        )
    
    try:
        events = analyzer.get_recent_events(hours=hours)
        all_events = events if events else []
    except:
        all_events = []
    
    total_events = len(all_events)
    critical = sum(1 for e in all_events if e.get('severity') == 'critical')
    high = sum(1 for e in all_events if e.get('severity') == 'high')
    medium = sum(1 for e in all_events if e.get('severity') == 'medium')
    unique_ips = len(set(e.get('ip_address') for e in all_events if e.get('ip_address'))) if all_events else 0
    
    summary_cards = html.Div([
        create_summary_card("Total Events", total_events, "", "
        create_summary_card("Critical", critical, "", "
        create_summary_card("High Severity", high, "", "
        create_summary_card("Medium Severity", medium, "", "
        create_summary_card("Unique IPs", unique_ips, "", "
    ], style={'display': 'flex', 'gap': '20px', 'flexWrap': 'wrap'})
    
    timeline_fig = create_timeline_chart(all_events)
    
    severity_fig = create_severity_pie_chart(all_events)
    
    top_attackers_fig = create_top_attackers_chart(all_events)
    
    attack_types_fig = create_attack_types_chart(all_events)
    
    hourly_fig = create_hourly_pattern_chart(all_events)
    
    resource_fig = create_resource_access_chart(all_events)
    
    recent_table = create_recent_events_table(all_events[:10])
    
    return (summary_cards, timeline_fig, severity_fig, top_attackers_fig, 
            attack_types_fig, hourly_fig, resource_fig, recent_table)


def create_summary_card(title, value, emoji, color):
    return html.Div([
        html.Div([
            html.Div(title, style={'fontSize': '13px', 'color': '#666666', 'marginBottom': '8px'}),
            html.Div([
                html.Span(str(value), style={'fontSize': '32px', 'fontWeight': '700', 'color': '#1a1a1a'})
            ], style={'display': 'flex', 'alignItems': 'baseline'})
        ])
    ], style={
        'backgroundColor': 'white',
        'padding': '24px',
        'borderRadius': '8px',
        'border': '1px solid
        'flex': '1',
        'minWidth': '200px',
        'transition': 'box-shadow 0.2s',
        'boxShadow': '0 1px 2px rgba(0,0,0,0.05)'
    })


def create_timeline_chart(events):
    if not events:
        fig = go.Figure()
        fig.update_layout(
            title="Events Over Time",
            annotations=[dict(text="No data available", showarrow=False, xref="paper", yref="paper", x=0.5, y=0.5, font=dict(size=14, color="
        )
        return fig
    
    from collections import defaultdict
    
    hourly_counts = defaultdict(int)
    
    for event in events:
        timestamp = event.get('timestamp')
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
    
        if timestamp.tzinfo is not None:
            timestamp = timestamp.replace(tzinfo=None)
        hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
        hourly_counts[hour_key] += 1
    
    hours = sorted(hourly_counts.keys())
    counts = [hourly_counts[h] for h in hours]
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=hours, y=counts, 
        mode='lines+markers',
        line=dict(color='
        marker=dict(size=8, color='
        fill='tozeroy',
        fillcolor='rgba(37, 99, 235, 0.1)'
    ))
    fig.update_layout(
        title=dict(text="Events Over Time", font=dict(size=16, color="
        xaxis_title="Time",
        yaxis_title="Event Count",
        template="plotly_white",
        plot_bgcolor='white',
        paper_bgcolor='white',
        font=dict(family="-apple-system, BlinkMacSystemFont, Segoe UI, Roboto", color="
        margin=dict(l=60, r=30, t=60, b=60),
        hovermode='x unified'
    )
    return fig


def create_severity_pie_chart(events):
    if not events:
        fig = go.Figure()
        fig.update_layout(title="Severity Distribution")
        return fig
    
    severity_counts = {}
    for event in events:
        severity = event.get('severity')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    colors = {'critical': '#dc3545', 'high': '#ff9800', 'medium': '#ffc107', 'low': '#28a745'}
    
    fig = go.Figure(data=[go.Pie(
        labels=list(severity_counts.keys()),
        values=list(severity_counts.values()),
        marker=dict(colors=[colors.get(s, '#6c757d') for s in severity_counts.keys()])
        textinfo='label+percent',
        textfont=dict(size=13),
        hole=0.4
    )])
    fig.update_layout(
        title=dict(text="Severity Distribution", font=dict(size=16, color="#1a1a1a"))
        template="plotly_white",
        plot_bgcolor='white',
        paper_bgcolor='white',
        font=dict(family="-apple-system, BlinkMacSystemFont, Segoe UI, Roboto", color="
        margin=dict(l=30, r=30, t=60, b=30),
        showlegend=True,
        legend=dict(orientation="v", yanchor="middle", y=0.5, xanchor="left", x=1)
    )
    return fig


def create_top_attackers_chart(events):
    if not events:
        fig = go.Figure()
        fig.update_layout(title="Top Attacker IPs")
        return fig
    
    from collections import Counter
    ip_counts = Counter(e.get('ip_address') for e in events if e.get('ip_address'))
    top_ips = ip_counts.most_common(10)
    
    fig = go.Figure(data=[go.Bar(
        x=[ip for ip, _ in top_ips],
        y=[count for _, count in top_ips],
        marker=dict(color='
        text=[count for _, count in top_ips],
        textposition='outside'
    )])
    fig.update_layout(
        title=dict(text="Top Attacker IPs", font=dict(size=16, color="
        xaxis_title="IP Address",
        yaxis_title="Event Count",
        template="plotly_white",
        plot_bgcolor='white',
        paper_bgcolor='white',
        font=dict(family="-apple-system, BlinkMacSystemFont, Segoe UI, Roboto", color="
        margin=dict(l=60, r=30, t=60, b=80),
        xaxis=dict(tickangle=-45)
    )
    return fig


def create_attack_types_chart(events):
    if not events:
        fig = go.Figure()
        fig.update_layout(title="Attack Types")
        return fig
    
    from collections import Counter
    type_counts = Counter(e.get('event_type', '').replace('_', ' ').title() for e in events)
    
    fig = go.Figure(data=[go.Bar(
        x=list(type_counts.keys()),
        y=list(type_counts.values()),
        marker=dict(color='
        text=list(type_counts.values()),
        textposition='outside'
    )])
    fig.update_layout(
        title=dict(text="Attack Types", font=dict(size=16, color="
        xaxis_title="Type",
        yaxis_title="Count",
        template="plotly_white",
        plot_bgcolor='white',
        paper_bgcolor='white',
        font=dict(family="-apple-system, BlinkMacSystemFont, Segoe UI, Roboto", color="
        margin=dict(l=60, r=30, t=60, b=80),
        xaxis=dict(tickangle=-45)
    )
    return fig


def create_hourly_pattern_chart(events):
    if not events:
        fig = go.Figure()
        fig.update_layout(title="Hourly Activity Pattern")
        return fig
    
    from collections import defaultdict
    hourly = defaultdict(int)
    
    for event in events:
        timestamp = event.get('timestamp')
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)

        if timestamp.tzinfo is not None:
            timestamp = timestamp.replace(tzinfo=None)
        hourly[timestamp.hour] += 1
    
    hours = list(range(24))
    counts = [hourly[h] for h in hours]
    
    fig = go.Figure(data=[go.Bar(
        x=hours,
        y=counts,
        marker=dict(color='
        text=counts,
        textposition='outside'
    )])
    fig.update_layout(
        title=dict(text="Hourly Activity Pattern", font=dict(size=16, color="
        xaxis_title="Hour of Day (24h)",
        yaxis_title="Event Count",
        template="plotly_white",
        plot_bgcolor='white',
        paper_bgcolor='white',
        font=dict(family="-apple-system, BlinkMacSystemFont, Segoe UI, Roboto", color="
        margin=dict(l=60, r=30, t=60, b=60),
        xaxis=dict(dtick=2)
    )
    return fig


def create_resource_access_chart(events):
    if not events:
        fig = go.Figure()
        fig.update_layout(title="Most Accessed Resources")
        return fig
    
    from collections import Counter
    resource_counts = Counter(e.get('resource') for e in events if e.get('resource'))
    top_resources = resource_counts.most_common(10)
    
    labels = [r[:40] + '...' if len(r) > 40 else r for r, _ in top_resources]
    
    fig = go.Figure(data=[go.Bar(
        y=labels,
        x=[count for _, count in top_resources],
        orientation='h',
        marker=dict(color='
        text=[count for _, count in top_resources],
        textposition='outside'
    )])
    fig.update_layout(
        title=dict(text="Most Accessed Resources", font=dict(size=16, color="
        xaxis_title="Access Count",
        yaxis_title="Resource",
        template="plotly_white",
        plot_bgcolor='white',
        paper_bgcolor='white',
        font=dict(family="-apple-system, BlinkMacSystemFont, Segoe UI, Roboto", color="
        margin=dict(l=200, r=30, t=60, b=60),
        height=450
    )
    return fig


def create_recent_events_table(events):
    if not events:
        return html.Div("No recent events to display", 
                       style={'textAlign': 'center', 'padding': '40px', 'color': '#666666'})
    
    severity_colors = {
        'critical': '#dc3545',
        'high': '#ff9800',
        'medium': '#ffc107',
        'low': '#28a745'
    }
    
    rows = []
    for event in events:
        timestamp = event.get('timestamp')
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)

        if timestamp.tzinfo is not None:
            timestamp = timestamp.replace(tzinfo=None)
        
        event_type = event.get('event_type', 'unknown')
        severity = event.get('severity', 'low')
        ip_address = event.get('ip_address', 'N/A')
        resource = event.get('resource', 'N/A')
        
        rows.append(html.Tr([
            html.Td(timestamp.strftime('%Y-%m-%d %H:%M:%S'), 
                   style={'padding': '16px', 'fontSize': '13px', 'color': '#1a1a1a'}),
            html.Td(event_type.replace('_', ' ').title(), 
                   style={'padding': '16px', 'fontSize': '13px', 'color': '#1a1a1a'})
            html.Td(
                html.Span(severity.upper(), 
                         style={
                             'padding': '4px 12px',
                             'borderRadius': '12px',
                             'fontSize': '11px',
                             'fontWeight': '600',
                             'color': 'white',
                             'backgroundColor': severity_colors.get(severity, '#6c757d'),
                             'textTransform': 'uppercase',
                             'letterSpacing': '0.5px'
                         }), 
                style={'padding': '16px'}),
            html.Td(ip_address, 
                   style={'padding': '16px', 'fontFamily': 'monospace', 'fontSize': '13px', 'color': '#1a1a1a'}),
            html.Td(resource[:45] + '...' if len(resource) > 45 else resource,
                   style={'padding': '16px', 'fontSize': '12px', 'color': '#666666'})
        ], style={'borderBottom': '1px solid #e0e0e0'})
    
    table = html.Table([
        html.Thead(html.Tr([
            html.Th('Timestamp', style={
                'padding': '16px',
                'textAlign': 'left',
                'backgroundColor': '#f8f9fa',
                'color': '#495057',
                'fontSize': '12px',
                'fontWeight': '600',
                'textTransform': 'uppercase',
                'letterSpacing': '0.5px',
                'borderBottom': '2px solid #dee2e6'
            }),
            html.Th('Event Type', style={
                'padding': '16px',
                'textAlign': 'left',
                'backgroundColor': '#f8f9fa',
                'color': '#495057',
                'fontSize': '12px',
                'fontWeight': '600',
                'textTransform': 'uppercase',
                'letterSpacing': '0.5px',
                'borderBottom': '2px solid #dee2e6'
            }),
            html.Th('Severity', style={
                'padding': '16px',
                'textAlign': 'left',
                'backgroundColor': '#f8f9fa',
                'color': '#495057',
                'fontSize': '12px',
                'fontWeight': '600',
                'textTransform': 'uppercase',
                'letterSpacing': '0.5px',
                'borderBottom': '2px solid #dee2e6'
            }),
            html.Th('Source IP', style={
                'padding': '16px',
                'textAlign': 'left',
                'backgroundColor': '#f8f9fa',
                'color': '#495057',
                'fontSize': '12px',
                'fontWeight': '600',
                'textTransform': 'uppercase',
                'letterSpacing': '0.5px',
                'borderBottom': '2px solid #dee2e6'
            }),
            html.Th('Resource', style={
                'padding': '16px',
                'textAlign': 'left',
                'backgroundColor': '#f8f9fa',
                'color': '#495057',
                'fontSize': '12px',
                'fontWeight': '600',
                'textTransform': 'uppercase',
                'letterSpacing': '0.5px',
                'borderBottom': '2px solid #dee2e6'
            }),
        ])),
        html.Tbody(rows)
    ], style={
        'width': '100%',
        'borderCollapse': 'collapse',
        'backgroundColor': 'white',
        'border': '1px solid
        'borderRadius': '8px',
        'overflow': 'hidden'
    })
    
    return table


if __name__ == '__main__':
    port = int(os.getenv('DASHBOARD_PORT', 8050))
    host = os.getenv('DASHBOARD_HOST', '0.0.0.0')
    
    print(f"""
Dashboard: http://localhost:{port}
Auto-refresh: 60 seconds
Region: {region}

Press Ctrl+C to stop the server
""")
    
    app.run(debug=True, host=host, port=port)
