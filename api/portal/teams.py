# controllers/teams.py
from flask_restful import Resource, Api
from flask import request, Blueprint, g

from portal.models import Team, User
from portal.services.team_service import TeamService
from portal.auth import login_required
from portal.utils import requires_perm

from extensions.ext_database import db

import logging

logger = logging.getLogger(__name__)

teams_bp = Blueprint('teams', __name__)
api = Api(teams_bp)

class TeamsAPI(Resource):
    @login_required
    @requires_perm('manage', 'team')
    def post(self):
        # Create a new team
        data = request.get_json()
        name = data.get('name')
        description = data.get('description')

        team = Team(name=name, description=description)
        db.session.add(team)
        db.session.commit()

        return {'message': 'Team created', 'team': team.to_dict()}, 201

    @login_required
    @requires_perm('read', 'team')
    def get(self):
        # Get list of teams
        teams = Team.query.all()
        return {'teams': [team.to_dict() for team in teams]}, 200

class TeamByIDAPI(Resource):
    @login_required
    @requires_perm('read', 'team')
    def get(self, team_id):
        # Get a specific team
        team = Team.query.get_or_404(team_id)
        return {'team': team.to_dict()}, 200

    @login_required
    @requires_perm('manage', 'team')
    def put(self, team_id):
        # Update a team
        team = Team.query.get_or_404(team_id)
        data = request.get_json()
        team.name = data.get('name', team.name)
        team.description = data.get('description', team.description)
        db.session.commit()
        return {'message': 'Team updated', 'team': team.to_dict()}, 200

    @login_required
    @requires_perm('manage', 'team')
    def delete(self, team_id):
        # Delete a team
        team = Team.query.get_or_404(team_id)
        db.session.delete(team)
        db.session.commit()
        return {'message': 'Team deleted'}, 204

class TeamByNameAPI(Resource):
    @login_required
    @requires_perm('read', 'team')
    def get(self, name):
        try:
            # Get a specific team by name
            print(name)
            #user = User.query.filter_by(username=username).first()

            team = Team.query.filter_by(name=name).first_or_404()
            logger.info(f"Retrieved team by name: {team.to_dict()}")
            return {'team': team.to_dict()}, 200
        except Exception as e:
            logger.error(f"Error retrieving team by name: {e}")
            return {"error": "Error retrieving team by name: " + str(e)}, 500

    @login_required
    @requires_perm('manage', 'team')
    def delete(self, name):
        try:
            # Delete a team by name
            team = Team.query.filter_by(name=name).first_or_404()
            db.session.delete(team)
            db.session.commit()

            logger.info(f"Deleted team by name: {team.to_dict()}")
            return {'message': 'Team deleted'}, 204
        except Exception as e:
            logger.error(f"Error deleting team by name: {e}")
            return {"error": "Error deleting team by name: " + str(e)}, 500
    
class TeamMembersAPI(Resource):
    @login_required
    @requires_perm('view', 'team')
    def get(self, team_id):
        # Get list of team members
        team = Team.query.get_or_404(team_id)
        return {'members': [member.to_dict() for member in team.members]}, 200

    @login_required
    @requires_perm('manage', 'team')
    def post(self, team_id):
        # Add a member to a team
        team = Team.query.get_or_404(team_id)
        data = request.get_json()
        user_id = data.get('user_id')
        user = User.query.get_or_404(user_id)
        team.members.append(user)
        db.session.commit()
        return {'message': 'User added to team', 'team': team.to_dict()}, 201

    @login_required
    @requires_perm('manage', 'team')
    def delete(self, team_id):
        # Remove a member from a team
        team = Team.query.get_or_404(team_id)
        data = request.get_json()
        user_id = data.get('user_id')
        user = User.query.get_or_404(user_id)
        team.members.remove(user)
        db.session.commit()
        return {'message': 'User removed from team', 'team': team.to_dict()}, 204
    
class TeamMembersByNameAPI(Resource):
    @login_required
    @requires_perm('view', 'team')
    def get(self, name):
        try:
            # Get list of team members by team name
            team = Team.query.filter_by(name=name).first_or_404()
            logger.info(f"Retrieved members for team by name: {team.to_dict()}")
            return {'members': [member.to_dict() for member in team.members]}, 200
        except Exception as e:
            logger.error(f"Error retrieving team members by name: {e}")
            return {"error": "Error retrieving team members by name: " + str(e)}, 500

    @login_required
    @requires_perm('manage', 'team')
    def post(self, name):
        try:
            # Add a member to a team by team name
            team = Team.query.filter_by(name=name).first_or_404()
            data = request.get_json()
            user_id = data.get('user_id')
            result = TeamService.add_member_to_teams(user_id, [team.id])
            if "error" in result:
                return result, 400
            return result, 200
        except Exception as e:
            logger.error(f"Error adding member to team by name: {e}")
            return {"error": "Error adding member to team by name: " + str(e)}, 500

    @login_required
    @requires_perm('manage', 'team')
    def delete(self, name):
        try:
            # Remove a member from a team by team name
            team = Team.query.filter_by(name=name).first_or_404()
            data = request.get_json()
            user_id = data.get('user_id')
            result = TeamService.remove_member_from_teams(user_id, [team.id])
            if "error" in result:
                return result, 400
            return result, 200
        except Exception as e:
            logger.error(f"Error removing member from team by name: {e}")
            return {"error": "Error removing member from team by name: " + str(e)}, 500

class AddUserToTeamByUsernameAPI(Resource):
    @login_required
    @requires_perm('manage', 'team')
    def post(self, team_name):
        try:
            data = request.get_json()
            username = data.get('username')
            result = TeamService.add_user_to_team_by_username_and_team_name(username, team_name)
            if "error" in result:
                return result, 400
            return result, 200
        except Exception as e:
            logger.error(f"Error adding user to team by username: {e}")
            return {"error": "Error adding user to team by username: " + str(e)}, 500

# Add the routes at the bottom
api.add_resource(TeamsAPI, "/teams")
api.add_resource(TeamByIDAPI, "/teams/<int:team_id>")
api.add_resource(TeamByNameAPI, "/teams/name/<string:name>")
api.add_resource(TeamMembersAPI, "/teams/<int:team_id>/members")
api.add_resource(TeamMembersByNameAPI, "/teams/name/<string:name>/members")
api.add_resource(AddUserToTeamByUsernameAPI, "/teams/name/<string:team_name>/add_user")