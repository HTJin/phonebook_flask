from flask import Blueprint, render_template, request, redirect, url_for
from flask_login import login_required, current_user
from ..forms import AddressForm
from ..models import Address, db

site = Blueprint('site', __name__, template_folder='site_templates')

@site.route('/')
def home():
    return render_template('index.html')

@site.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    my_address = AddressForm()
    try:
        if request.method == 'POST' and my_address.validate_on_submit():
            street = my_address.street.data
            city = my_address.city.data
            state = my_address.state.data
            zipcode = my_address.zipcode.data
            user_token = current_user.token

            address = Address(street, city, state, zipcode, user_token)
            db.session.add(address)
            db.session.commit()

            return redirect(url_for('site.profile'))
    except:
        raise Exception('Something aint right')

    current_user_token = current_user.token
    addresses = Address.query.filter_by(user_token=current_user_token)

    return render_template('profile.html', form=my_address, addresses=addresses, our_user=current_user)