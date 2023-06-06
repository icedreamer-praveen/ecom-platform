import requests
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse, reverse_lazy
from django.views.generic import (CreateView, DetailView, FormView, ListView,
                                  TemplateView, View)

from .forms import (CheckoutForm, CustomerLoginForm, CustomerRegistrationForm,
                    PasswordForgotForm, PasswordResetForm, ProductForm)
from .models import (ORDER_STATUS, Admin, Cart, CartProduct, Category,
                     Customer, Order, Product, ProductImage, User)
from .utils import password_reset_token


class EcomMixin(object):
    def dispatch(self, request, *args, **kwargs):
        """
        This function assigns a customer to a cart object if the user is authenticated and has a
        customer account.
        
        :param request: The HTTP request object that contains information about the current request,
        such as the HTTP method, headers, and data
        :return: The `dispatch` method of a class is being returned, which is called when a request is
        made to the associated view. The method checks if a cart object exists in the session and if the
        user is authenticated. If both conditions are met, it assigns the cart to the authenticated user
        and saves the changes. Finally, it calls the `dispatch` method of the parent class with the same
        arguments and
        """
        cart_id = request.session.get("cart_id")
        if cart_id:
            cart_obj = Cart.objects.get(id=cart_id)
            if request.user.is_authenticated and request.user.customer:
                cart_obj.customer = request.user.customer
                cart_obj.save()
        return super().dispatch(request, *args, **kwargs)


class HomeView(EcomMixin, TemplateView):
    template_name = "home.html"

    def get_context_data(self, **kwargs):
        """
        This function adds a list of products to the context data for a web page, with pagination.
        :return: a dictionary object `context` which contains the key-value pairs of `myname` and
        `product_list`. The `myname` key has a string value "Praveen Chaudhary" and the `product_list` key
        has a list of `Product` objects that are paginated with 8 items per page.
        """
        context = super().get_context_data(**kwargs)
        context['myname'] = "Praveen Chaudhary"
        all_products = Product.objects.all().order_by("-id")
        paginator = Paginator(all_products, 8)
        page_number = self.request.GET.get('page')
        print(page_number)
        product_list = paginator.get_page(page_number)
        context['product_list'] = product_list
        return context


class AllProductsView(EcomMixin, TemplateView):
    template_name = "allproducts.html"

    def get_context_data(self, **kwargs):
        """
        This function adds all categories to the context data of a view in Django.
        :return: The `get_context_data` method is returning a dictionary object `context` which contains
        all the key-value pairs from the `super()` method's `get_context_data` method, as well as an
        additional key-value pair where the key is `'allcategories'` and the value is a QuerySet of all
        `Category` objects.
        """
        context = super().get_context_data(**kwargs)
        context['allcategories'] = Category.objects.all()
        return context


class ProductDetailView(EcomMixin, TemplateView):
    template_name = "productdetail.html"

    def get_context_data(self, **kwargs):
        """
        This function retrieves a product object based on a URL slug, increments its view count, adds it
        to the context dictionary, and returns the context.
        :return: The `get_context_data` method is returning a dictionary `context` that contains the
        `product` object with an updated `view_count` attribute. This method is used in a Django view to
        add additional context data to the template context.
        """
        context = super().get_context_data(**kwargs)
        url_slug = self.kwargs['slug']
        product = Product.objects.get(slug=url_slug)
        product.view_count += 1
        product.save()
        context['product'] = product
        return context


class AddToCartView(EcomMixin, TemplateView):
    template_name = "addtocart.html"

    def get_context_data(self, **kwargs):
        """
        This function adds a product to the cart and updates the cart's total price.
        :return: The `context` dictionary is being returned.
        """
        context = super().get_context_data(**kwargs)
        # get product id from requested url
        product_id = self.kwargs['pro_id']
        # get product
        product_obj = Product.objects.get(id=product_id)

        # check if cart exists
        cart_id = self.request.session.get("cart_id", None)
        if cart_id:
            cart_obj = Cart.objects.get(id=cart_id)
            this_product_in_cart = cart_obj.cartproduct_set.filter(
                product=product_obj)

            # item already exists in cart
            if this_product_in_cart.exists():
                cartproduct = this_product_in_cart.last()
                cartproduct.quantity += 1
                cartproduct.subtotal += product_obj.selling_price
                cartproduct.save()
                cart_obj.total += product_obj.selling_price
                cart_obj.save()
            # new item is added in cart
            else:
                cartproduct = CartProduct.objects.create(
                    cart=cart_obj, product=product_obj, rate=product_obj.selling_price, quantity=1, subtotal=product_obj.selling_price)
                cart_obj.total += product_obj.selling_price
                cart_obj.save()

        else:
            cart_obj = Cart.objects.create(total=0)
            self.request.session['cart_id'] = cart_obj.id
            cartproduct = CartProduct.objects.create(
                cart=cart_obj, product=product_obj, rate=product_obj.selling_price, quantity=1, subtotal=product_obj.selling_price)
            cart_obj.total += product_obj.selling_price
            cart_obj.save()

        return context


class ManageCartView(EcomMixin, View):
    def get(self, request, *args, **kwargs):
        """
        This function updates the quantity and subtotal of a CartProduct object and the total of its
        associated Cart object based on the action parameter passed in the request, and redirects to the
        mycart page.
        
        :param request: The HTTP request object that contains information about the current request,
        such as the user agent, headers, and query parameters
        :return: a redirect to the "ecomapp:mycart" URL.
        """
        cp_id = self.kwargs["cp_id"]
        action = request.GET.get("action")
        cp_obj = CartProduct.objects.get(id=cp_id)
        cart_obj = cp_obj.cart

        if action == "inc":
            cp_obj.quantity += 1
            cp_obj.subtotal += cp_obj.rate
            cp_obj.save()
            cart_obj.total += cp_obj.rate
            cart_obj.save()
        elif action == "dcr":
            cp_obj.quantity -= 1
            cp_obj.subtotal -= cp_obj.rate
            cp_obj.save()
            cart_obj.total -= cp_obj.rate
            cart_obj.save()
            if cp_obj.quantity == 0:
                cp_obj.delete()

        elif action == "rmv":
            cart_obj.total -= cp_obj.subtotal
            cart_obj.save()
            cp_obj.delete()
        else:
            pass
        return redirect("ecomapp:mycart")


class EmptyCartView(EcomMixin, View):
    def get(self, request, *args, **kwargs):
        """
        This function deletes all products from the cart and sets the total to zero.
        
        :param request: The HTTP request object that contains information about the current request,
        such as the user making the request, the HTTP method used, and any data submitted with the
        request
        :return: a redirect to the "mycart" URL of the "ecomapp" app.
        """
        cart_id = request.session.get("cart_id", None)
        if cart_id:
            cart = Cart.objects.get(id=cart_id)
            cart.cartproduct_set.all().delete()
            cart.total = 0
            cart.save()
        return redirect("ecomapp:mycart")


class MyCartView(EcomMixin, TemplateView):
    template_name = "mycart.html"

    def get_context_data(self, **kwargs):
        """
        This function retrieves the cart object from the session and adds it to the context data.
        :return: a dictionary object `context` which contains the `cart` object as one of its keys. The
        `cart` object is either retrieved from the database based on the `cart_id` stored in the session
        or set to `None` if `cart_id` is not found in the session.
        """
        context = super().get_context_data(**kwargs)
        cart_id = self.request.session.get("cart_id", None)
        if cart_id:
            cart = Cart.objects.get(id=cart_id)
        else:
            cart = None
        context['cart'] = cart
        return context


class CheckoutView(EcomMixin, CreateView):
    template_name = "checkout.html"
    form_class = CheckoutForm
    success_url = reverse_lazy("ecomapp:home")

    def dispatch(self, request, *args, **kwargs):
        """
        This function checks if the user is authenticated and has a customer account, and redirects to
        the login page if not.
        
        :param request: The HTTP request object that contains information about the current request,
        such as the requested URL, headers, and data
        :return: If the user is not authenticated or does not have a customer account, the function will
        redirect them to the login page with the next parameter set to "/checkout/". If the user is
        authenticated and has a customer account, the function will call the dispatch method of the
        parent class with the given request, args, and kwargs, and return its result.
        """
        if request.user.is_authenticated and request.user.customer:
            pass
        else:
            return redirect("/login/?next=/checkout/")
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        """
        This function retrieves the cart object from the session and adds it to the context data.
        :return: a dictionary object `context` which contains the `cart` object as one of its keys. The
        `cart` object is either a `Cart` object retrieved from the database based on the `cart_id` stored
        in the session, or `None` if the `cart_id` is not found in the session.
        """
        context = super().get_context_data(**kwargs)
        cart_id = self.request.session.get("cart_id", None)
        if cart_id:
            cart_obj = Cart.objects.get(id=cart_id)
        else:
            cart_obj = None
        context['cart'] = cart_obj
        return context

    def form_valid(self, form):
        """
        This function validates a form, creates an order object, sets its attributes, and redirects to a
        payment page based on the selected payment method.
        
        :param form: The form object that is being validated
        :return: The method is returning a redirect to either the "khaltirequest" or "esewarequest" view
        depending on the payment method selected in the form. If there is no cart_id in the session, it
        redirects to the "home" view. If none of these conditions are met, it calls the parent class's
        form_valid method.
        """
        cart_id = self.request.session.get("cart_id")
        if cart_id:
            cart_obj = Cart.objects.get(id=cart_id)
            form.instance.cart = cart_obj
            form.instance.subtotal = cart_obj.total
            form.instance.discount = 0
            form.instance.total = cart_obj.total
            form.instance.order_status = "Order Received"
            del self.request.session['cart_id']
            pm = form.cleaned_data.get("payment_method")
            order = form.save()
            if pm == "Khalti":
                return redirect(reverse("ecomapp:khaltirequest") + "?o_id=" + str(order.id))
            elif pm == "Esewa":
                return redirect(reverse("ecomapp:esewarequest") + "?o_id=" + str(order.id))
        else:
            return redirect("ecomapp:home")
        return super().form_valid(form)


class KhaltiRequestView(View):
    def get(self, request, *args, **kwargs):
        """
        This function retrieves an order object based on the provided ID and renders a template with the
        order object as context.
        
        :param request: The request parameter is an HttpRequest object that represents the current
        request made by the user. It contains information about the request, such as the HTTP method
        used (GET, POST, etc.), the URL requested, any query parameters, and more
        :return: The view is returning an HTTP response with the rendered "khaltirequest.html" template
        and a context dictionary containing the "order" object retrieved from the database based on the
        "o_id" parameter passed in the GET request.
        """
        o_id = request.GET.get("o_id")
        order = Order.objects.get(id=o_id)
        context = {
            "order": order
        }
        return render(request, "khaltirequest.html", context)


class KhaltiVerifyView(View):
    def get(self, request, *args, **kwargs):
        """
        This function verifies a payment using the Khalti API and updates the payment status of an order
        object.
        
        :param request: The HTTP request object that contains metadata about the request, such as headers
        and query parameters
        :return: A JSON response containing a boolean value indicating whether the payment was
        successfully verified or not.
        """
        token = request.GET.get("token")
        amount = request.GET.get("amount")
        o_id = request.GET.get("order_id")
        print(token, amount, o_id)

        url = "https://khalti.com/api/v2/payment/verify/"
        payload = {
            "token": token,
            "amount": amount
        }
        headers = {
            "Authorization": "Key test_secret_key_f59e8b7d18b4499ca40f68195a846e9b"
        }

        order_obj = Order.objects.get(id=o_id)

        response = requests.post(url, payload, headers=headers)
        resp_dict = response.json()
        if resp_dict.get("idx"):
            success = True
            order_obj.payment_completed = True
            order_obj.save()
        else:
            success = False
        data = {
            "success": success
        }
        return JsonResponse(data)


class EsewaRequestView(View):
    def get(self, request, *args, **kwargs):
        """
        This function retrieves an order object based on the provided ID and renders a template with the
        order object as context.
        
        :param request: The request parameter is an HttpRequest object that represents the current
        request made by the user. It contains information about the request, such as the HTTP method
        used (GET, POST, etc.), the URL requested, any query parameters, and more. It is passed to the
        view function as the first argument
        :return: an HTTP response with the rendered "esewarequest.html" template and a context
        dictionary containing the "order" object retrieved from the database based on the "o_id"
        parameter passed in the GET request.
        """
        o_id = request.GET.get("o_id")
        order = Order.objects.get(id=o_id)
        context = {
            "order": order
        }
        return render(request, "esewarequest.html", context)


class EsewaVerifyView(View):
    def get(self, request, *args, **kwargs):
        """
        This function processes a payment request using eSewa payment gateway and updates the payment
        status of an order accordingly.
        
        :param request: The HTTP request object that contains information about the current request,
        such as the request method, headers, and query parameters
        :return: If the status is "Success", the function returns a redirect to the homepage ("/"). If
        the status is not "Success", the function returns a redirect to the "/esewa-request/" page with
        the order ID as a query parameter.
        """
        import xml.etree.ElementTree as ET
        oid = request.GET.get("oid")
        amt = request.GET.get("amt")
        refId = request.GET.get("refId")

        url = "https://uat.esewa.com.np/epay/transrec"
        d = {
            'amt': amt,
            'scd': 'epay_payment',
            'rid': refId,
            'pid': oid,
        }
        resp = requests.post(url, d)
        root = ET.fromstring(resp.content)
        status = root[0].text.strip()

        order_id = oid.split("_")[1]
        order_obj = Order.objects.get(id=order_id)
        if status == "Success":
            order_obj.payment_completed = True
            order_obj.save()
            return redirect("/")
        else:

            return redirect("/esewa-request/?o_id="+order_id)


class CustomerRegistrationView(CreateView):
    template_name = "customerregistration.html"
    form_class = CustomerRegistrationForm
    success_url = reverse_lazy("ecomapp:home")

    def form_valid(self, form):
        """
        This function creates a new user with the provided username, email, and password, logs them in,
        and returns a valid form.
        
        :param form: The form parameter is an instance of a Django form that has been submitted by the
        user. It contains the data that the user has entered into the form fields. The form is validated
        using the clean methods defined in the form class, and if the data is valid, it is used to
        create a new
        :return: The `form_valid` method is returning the result of calling the `form_valid` method of
        the parent class using `super().form_valid(form)`. This is typically used in Django class-based
        views to perform additional actions after the form has been successfully validated. In this
        case, the method is creating a new user, logging them in, and then calling the parent
        `form_valid` method to complete
        """
        username = form.cleaned_data.get("username")
        password = form.cleaned_data.get("password")
        email = form.cleaned_data.get("email")
        user = User.objects.create_user(username, email, password)
        form.instance.user = user
        login(self.request, user)
        return super().form_valid(form)

    def get_success_url(self):
        """
        This function returns the next URL if it exists in the request GET parameters, otherwise it
        returns the default success URL.
        :return: The `get_success_url` method is returning the value of the `next_url` variable if it
        exists in the GET parameters of the request, otherwise it returns the value of the `success_url`
        attribute of the class.
        """
        if "next" in self.request.GET:
            next_url = self.request.GET.get("next")
            return next_url
        else:
            return self.success_url


class CustomerLogoutView(View):
    def get(self, request):
        """
        This function logs out the user and redirects them to the home page of the ecomapp.
        
        :param request: The request parameter is an object that represents the HTTP request made by the
        client to the server. It contains information such as the HTTP method used (GET, POST, etc.),
        the URL requested, any query parameters, headers, and the body of the request (if applicable).
        In this specific code snippet
        :return: The `redirect` function is being returned, which redirects the user to the "home" URL
        specified in the `ecomapp` namespace.
        """
        logout(request)
        return redirect("ecomapp:home")


class CustomerLoginView(FormView):
    template_name = "customerlogin.html"
    form_class = CustomerLoginForm
    success_url = reverse_lazy("ecomapp:home")

    # form_valid method is a type of post method and is available in createview formview and updateview
    def form_valid(self, form):
        """
        This function validates a form by checking if the username and password are correct and belong
        to a customer, and logs them in if they are valid.
        
        :param form: The form parameter is an instance of a Django form that has been submitted by the
        user. It contains the cleaned data entered by the user, which can be accessed using the
        `cleaned_data` attribute
        :return: The `form_valid` method is returning the result of calling the `form_valid` method of
        the parent class (using `super().form_valid(form)`). This is typically used to perform any
        additional processing that the parent class needs to do after the custom logic in the overridden
        method has been executed.
        """
        uname = form.cleaned_data.get("username")
        pword = form.cleaned_data["password"]
        usr = authenticate(username=uname, password=pword)
        if usr is not None and Customer.objects.filter(user=usr).exists():
            login(self.request, usr)
        else:
            return render(self.request, self.template_name, {"form": self.form_class, "error": "Invalid credentials"})

        return super().form_valid(form)

    def get_success_url(self):
        """
        This function returns the next URL if it exists in the request GET parameters, otherwise it
        returns the default success URL.
        :return: The `get_success_url` method is returning the value of the `next_url` variable if it
        exists in the GET parameters of the request, otherwise it returns the value of the `success_url`
        attribute of the class.
        """
        if "next" in self.request.GET:
            next_url = self.request.GET.get("next")
            return next_url
        else:
            return self.success_url


class AboutView(EcomMixin, TemplateView):
    template_name = "about.html"


class ContactView(EcomMixin, TemplateView):
    template_name = "contactus.html"


class CustomerProfileView(TemplateView):
    template_name = "customerprofile.html"

    def dispatch(self, request, *args, **kwargs):
        """
        This function checks if a user is authenticated and has a customer profile, and redirects them to
        the login page if not.
        
        :param request: The HTTP request object that contains information about the current request, such
        as the requested URL, headers, and data
        :return: If the user is not authenticated or is not a customer, the function will return a
        redirect to the login page with the next parameter set to /profile/. If the user is authenticated
        and is a customer, the function will call the dispatch method of the parent class and return its
        result.
        """
        if request.user.is_authenticated and Customer.objects.filter(user=request.user).exists():
            pass
        else:
            return redirect("/login/?next=/profile/")
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        """
        This function adds the customer and their orders to the context data for a view.
        :return: a dictionary object `context` which contains the `customer` and `orders` data. The
        `customer` data is obtained from the `request.user.customer` attribute and the `orders` data is
        obtained by filtering the `Order` objects based on the `customer` attribute of the `Cart` object
        and ordering them by descending `id`. The `context` dictionary is then
        """
        context = super().get_context_data(**kwargs)
        customer = self.request.user.customer
        context['customer'] = customer
        orders = Order.objects.filter(cart__customer=customer).order_by("-id")
        context["orders"] = orders
        return context


class CustomerOrderDetailView(DetailView):
    template_name = "customerorderdetail.html"
    model = Order
    context_object_name = "ord_obj"

    def dispatch(self, request, *args, **kwargs):
        """
        This function checks if a user is authenticated and has a customer profile, and if so, ensures
        that the user is accessing their own order before allowing access to the view.
        
        :param request: The HTTP request object that contains information about the current request,
        such as the HTTP method, headers, and data
        :return: If the user is authenticated and has a related customer object, the function checks if
        the order ID in the URL matches the order ID of the customer's cart. If they do not match, the
        function redirects the user to their profile page. If the user is not authenticated, the
        function redirects them to the login page with a "next" parameter set to redirect them to their
        profile page after logging in
        """
        if request.user.is_authenticated and Customer.objects.filter(user=request.user).exists():
            order_id = self.kwargs["pk"]
            order = Order.objects.get(id=order_id)
            if request.user.customer != order.cart.customer:
                return redirect("ecomapp:customerprofile")
        else:
            return redirect("/login/?next=/profile/")
        return super().dispatch(request, *args, **kwargs)


class SearchView(TemplateView):
    template_name = "search.html"

    def get_context_data(self, **kwargs):
        """
        This function retrieves search results for a keyword from the Product model and adds them to the
        context data.
        :return: This code is returning a context dictionary that includes the search results for a
        keyword query on the Product model. The search results are filtered based on whether the keyword
        appears in the title, description, or return policy fields of the Product model. The search
        results are then added to the context dictionary with the key "results".
        """
        context = super().get_context_data(**kwargs)
        kw = self.request.GET.get("keyword")
        results = Product.objects.filter(
            Q(title__icontains=kw) | Q(description__icontains=kw) | Q(return_policy__icontains=kw))
        print(results)
        context["results"] = results
        return context


class PasswordForgotView(FormView):
    template_name = "forgotpassword.html"
    form_class = PasswordForgotForm
    success_url = "/forgot-password/?m=s"

    def form_valid(self, form):
        """
        This function sends a password reset link to a user's email address.
        
        :param form: The form parameter is an instance of the form class that the form_valid method is
        defined in. It contains the cleaned data submitted by the user
        :return: The `form_valid` method is returning the result of calling the `form_valid` method of
        the parent class, which is a `HttpResponseRedirect` object that redirects the user to the
        success URL specified in the view.
        """
        # get email from user
        email = form.cleaned_data.get("email")
        # get current host ip/domain
        url = self.request.META['HTTP_HOST']
        # get customer and then user
        customer = Customer.objects.get(user__email=email)
        user = customer.user
        # send mail to the user with email
        text_content = 'Please Click the link below to reset your password. '
        html_content = url + "/password-reset/" + email + \
            "/" + password_reset_token.make_token(user) + "/"
        send_mail(
            'Password Reset Link | Django Ecommerce',
            text_content + html_content,
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
        return super().form_valid(form)


class PasswordResetView(FormView):
    template_name = "passwordreset.html"
    form_class = PasswordResetForm
    success_url = "/login/"

    def dispatch(self, request, *args, **kwargs):
        """
        This function checks if a user's password reset token is valid and redirects them if it is not.
        
        :param request: The HTTP request object that contains information about the current request,
        such as the HTTP method, headers, and body
        :return: If the user is not found or the password reset token is invalid, the function will
        return a redirect to the password reset page with a query parameter "m=e". Otherwise, it will
        call the dispatch method of the parent class and return its result.
        """
        email = self.kwargs.get("email")
        user = User.objects.get(email=email)
        token = self.kwargs.get("token")
        if user is not None and password_reset_token.check_token(user, token):
            pass
        else:
            return redirect(reverse("ecomapp:passworforgot") + "?m=e")

        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        """
        This function sets a new password for a user and saves it to the database.
        
        :param form: The form object that was submitted by the user
        :return: The `form_valid` method is returning the result of calling the `form_valid` method of
        the parent class using `super().form_valid(form)`. This is typically used in Django class-based
        views to handle form validation and processing.
        """
        password = form.cleaned_data['new_password']
        email = self.kwargs.get("email")
        user = User.objects.get(email=email)
        user.set_password(password)
        user.save()
        return super().form_valid(form)

# admin pages


class AdminLoginView(FormView):
    template_name = "adminpages/adminlogin.html"
    form_class = CustomerLoginForm
    success_url = reverse_lazy("ecomapp:adminhome")

    def form_valid(self, form):
        """
        This function validates a form by checking if the username and password are correct and belong
        to an admin user, and logs them in if they are valid.
        
        :param form: The form parameter is an instance of a Django form that has been submitted by the
        user. It contains the cleaned data entered by the user, which has been validated by the form's
        validation rules
        :return: If the user is authenticated and is an admin, the user is logged in and the view's
        `form_valid` method is called. If the user is not authenticated or is not an admin, the view
        returns a rendered template with an error message indicating that the credentials are invalid.
        """
        uname = form.cleaned_data.get("username")
        pword = form.cleaned_data["password"]
        usr = authenticate(username=uname, password=pword)
        if usr is not None and Admin.objects.filter(user=usr).exists():
            login(self.request, usr)
        else:
            return render(self.request, self.template_name, {"form": self.form_class, "error": "Invalid credentials"})
        return super().form_valid(form)


class AdminRequiredMixin(object):
    def dispatch(self, request, *args, **kwargs):
        """
        This function checks if the user is authenticated and an admin, and redirects to the admin login
        page if not.
        
        :param request: The HTTP request object that contains information about the current request, such
        as the requested URL, headers, and data
        :return: If the user is not authenticated or is not an admin, the function will return a redirect
        to "/admin-login/". If the user is authenticated and is an admin, the function will call the
        parent dispatch method with the given request, args, and kwargs.
        """
        if request.user.is_authenticated and Admin.objects.filter(user=request.user).exists():
            pass
        else:
            return redirect("/admin-login/")
        return super().dispatch(request, *args, **kwargs)


class AdminHomeView(AdminRequiredMixin, TemplateView):
    template_name = "adminpages/adminhome.html"

    def get_context_data(self, **kwargs):
        """
        This function adds a queryset of orders with the status "Order Received" to the context
        dictionary.
        :return: The `get_context_data` method is returning a dictionary `context` which contains a
        key-value pair where the key is `"pendingorders"` and the value is a queryset of `Order` objects
        filtered by `order_status` equal to `"Order Received"` and ordered by descending `id`. This
        queryset is obtained by calling the `filter` and `order_by` methods on the `Order` model
        """
        context = super().get_context_data(**kwargs)
        context["pendingorders"] = Order.objects.filter(
            order_status="Order Received").order_by("-id")
        return context


class AdminOrderDetailView(AdminRequiredMixin, DetailView):
    template_name = "adminpages/adminorderdetail.html"
    model = Order
    context_object_name = "ord_obj"

    def get_context_data(self, **kwargs):
        """
        This function adds a dictionary of order statuses to the context data of a Django view.
        :return: The `get_context_data` method is returning a dictionary `context` that contains a
        key-value pair where the key is `"allstatus"` and the value is `ORDER_STATUS`. The
        `super().get_context_data(**kwargs)` method is calling the parent class's `get_context_data`
        method and returning its context data, which is then updated with the `"allstatus"` key-value
        pair before being
        """
        context = super().get_context_data(**kwargs)
        context["allstatus"] = ORDER_STATUS
        return context


class AdminOrderListView(AdminRequiredMixin, ListView):
    template_name = "adminpages/adminorderlist.html"
    queryset = Order.objects.all().order_by("-id")
    context_object_name = "allorders"


class AdminOrderStatuChangeView(AdminRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        """
        This function updates the status of an order and redirects to the order detail page.
        
        :param request: The HTTP request object that contains information about the current request,
        such as the HTTP method, headers, and data
        :return: The view is returning an HTTP redirect response to the admin order detail page for the
        updated order object.
        """
        order_id = self.kwargs["pk"]
        order_obj = Order.objects.get(id=order_id)
        new_status = request.POST.get("status")
        order_obj.order_status = new_status
        order_obj.save()
        return redirect(reverse_lazy("ecomapp:adminorderdetail", kwargs={"pk": order_id}))


class AdminProductListView(AdminRequiredMixin, ListView):
    template_name = "adminpages/adminproductlist.html"
    queryset = Product.objects.all().order_by("-id")
    context_object_name = "allproducts"


class AdminProductCreateView(AdminRequiredMixin, CreateView):
    template_name = "adminpages/adminproductcreate.html"
    form_class = ProductForm
    success_url = reverse_lazy("ecomapp:adminproductlist")

    def form_valid(self, form):
        """
        This function saves a form, retrieves a list of images from the request, and creates a new
        ProductImage object for each image with the saved form as the product.
        
        :param form: The form parameter is an instance of the form class that is being used to validate
        and save the data submitted by the user. It contains the cleaned and validated data that can be
        used to create a new instance of the model associated with the form
        :return: The `form_valid` method is returning the result of calling the `form_valid` method of
        the parent class using `super().form_valid(form)`. This is typically used to save the form data
        and redirect the user to a success page.
        """
        p = form.save()
        images = self.request.FILES.getlist("more_images")
        for i in images:
            ProductImage.objects.create(product=p, image=i)
        return super().form_valid(form)
