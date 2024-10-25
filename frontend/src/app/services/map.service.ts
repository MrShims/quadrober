import { Inject, Injectable, signal } from '@angular/core';
import { LngLat, YMap, YMapLocationRequest } from 'ymaps3';
import { DOCUMENT } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { debounceTime, Subject, switchMap, tap } from 'rxjs';
import { GeocoderResponse } from '../models/geocoder-response';
import { ToastService } from './toast.service';

export enum MapState {
  INITIAL,
  FILLING_FORM_ADDRESS,
  FILLING_FORM_DATETIME,
}

@Injectable({
  providedIn: 'root'
})
export class MapService {
  mapState = signal(MapState.INITIAL);
  addPointContainer: HTMLElement | null = null;
  yandexPath = 'https://geocode-maps.yandex.ru/1.x/';
  apiKey = '3aa9f3c7-cef8-4674-8143-9764dfe005ea';
  pointCoordinates$ = new Subject<LngLat>();
  preparedCoordinates$ = this.pointCoordinates$.asObservable().pipe(
    debounceTime(250),
    switchMap((coordinates) => {
      return this.http.get<GeocoderResponse>(this.yandexPath, { params: { apikey: this.apiKey, geocode: coordinates.join(','), format: 'json' } });
    }),
  );

  map: YMap | undefined;

  // Не разобрался с типами.
  // Сохраняю в переменную, чтобы потом удалять,
  // когда хочу добавить новую точку для встречи
  meetingPoint: any;

  constructor(
    private readonly http: HttpClient,
    private readonly toastService: ToastService,
    @Inject(DOCUMENT) private document: Document
  ) {
    this.initMap();
    this.showHintToast();
  }

  async initMap() {
    await ymaps3.ready;

    // await ymaps3.ready.then(() => {
    //   ymaps3.import.registerCdn('https://cdn.jsdelivr.net/npm/{package}', ['@yandex/ymaps3-default-ui-theme@latest']);
    // });

    const { YMap, YMapDefaultSchemeLayer, YMapDefaultFeaturesLayer } = ymaps3;

    const defaultLocation: YMapLocationRequest = { center: [37.623082, 55.75254], zoom: 15 }

    this.map = new YMap(this.document.getElementById('map') as HTMLElement, { location: defaultLocation });

    this.map.addChild(new YMapDefaultSchemeLayer({})).addChild(new YMapDefaultFeaturesLayer({}));

    this.requestLocation();
  }

  requestLocation() {
    navigator.geolocation.getCurrentPosition((position) => {
      let location: YMapLocationRequest = {
        center: [position.coords.longitude, position.coords.latitude],
        zoom: 15,
      };

      this.setLocation(location);
      this.setMarkerWithMe([position.coords.longitude, position.coords.latitude]);
    });
  }

  async setMarkerWithMe(coordinates: number[]) {
    try {
      // @ts-ignore
      const {YMapDefaultMarker} = await ymaps3.import('@yandex/ymaps3-default-ui-theme');

      const mePoint = new YMapDefaultMarker({
        coordinates: coordinates as LngLat,
        draggable: false,
        title: 'Вы сейчас здесь',
      }) as any;

      this.map?.addChild(mePoint)
    } catch (e) {

    }
  }

  setLocation(location: YMapLocationRequest) {
    this.map?.setLocation(location);
  }

  /**
   * Создать ползунок для выбора места встречи
   */
  async addPoint({ coordinates, draggable, title, subtitle }: {
    coordinates?: LngLat,
    draggable?: boolean,
    title?: string,
    subtitle?: string,
  } = {}) {
    try {
      // @ts-ignore
      const {YMapDefaultMarker} = await ymaps3.import('@yandex/ymaps3-default-ui-theme');

      if (this.meetingPoint) {
        this.map?.removeChild(this.meetingPoint);
      }

      this.meetingPoint = new YMapDefaultMarker({
        coordinates: coordinates || this.map?.center as LngLat,
        draggable: draggable === false ? false : true,
        title: title || 'Место встречи',
        subtitle: subtitle || 'Передвигайте ползунок',
        // onDragMove: this.onDragMovePointAHandler,
        onDragEnd: this.onDragEndHandler.bind(this),
      }) as any;

      this.map?.addChild(this.meetingPoint)
    } catch (e) {

    }
  }

  addPointFromInput(coordinates: LngLat) {
    let location: YMapLocationRequest = {
      center: coordinates,
      zoom: 15,
    };

    this.map?.setLocation(location);
    this.addPoint({ coordinates });
  }

  // Принимает адрес стрингой, чтобы посмотреть координаты
  getCoordinatesByAddress(address: string) {
    return this.http.get<GeocoderResponse>(this.yandexPath, { params: { apikey: this.apiKey, geocode: address, format: 'json' } });
  }

  // Отслеживает конечную точку ползунка
  onDragEndHandler(event: LngLat) {
    this.pointCoordinates$.next(event);
    this.addPointContainer = this.document.querySelector('.add-point-container');
    if (this.addPointContainer) {
      this.addPointContainer.style.display = 'block';
      this.addPointContainer.style.opacity = '1';
    }
  }

  chooseOnMap() {
    this.addPointContainer = this.document.querySelector('.add-point-container');
    if (this.addPointContainer) {
      this.addPointContainer.style.transition = '300ms';
      this.addPointContainer.style.opacity = '0';

      setTimeout(() => {
        if (this.addPointContainer) {
          this.addPointContainer.style.display = 'none';
        }
      }, 300);
    }
  }

  setMapState(state: MapState) {
    this.mapState.set(state);
    this.showHintToast();
  }

  removeMeetingPoint() {
    this.map?.removeChild(this.meetingPoint);
  }

  private showHintToast() {
    this.toastService.clear();

    let hintText = '';

    switch (this.mapState()) {
      case MapState.FILLING_FORM_ADDRESS:
        hintText = 'Перенесите ползунок или введите в поисковой строке место, где будет встреча';
        break;
      case MapState.FILLING_FORM_DATETIME:
        hintText = 'Выберите дату и время, когда вы планируете придти в указанное место';
        break;
      case MapState.INITIAL:
        hintText = 'Выберите уже существующую встречу или создайте свою нажав на кнопку "Запланировать встречу"';
        break;
    }

    this.toastService.show({
      text: hintText,
      classname: 'bg-primary text-light',
      delay: 10000,
    });
  }
}
